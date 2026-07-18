package identity

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CeremonySession is a single-use WebAuthn challenge (registration or login).
type CeremonySession struct {
	Challenge            string
	UserID               string // UUID v7
	UserEmail            string // plain email for WebAuthn display
	TenantID             string
	UserHandle           []byte // WebAuthn handle — must match PasskeyUser.WebAuthnID()
	AllowedCredentialIDs [][]byte
	Expires              int64
	UserVerification     string
	WASession            *webauthn.SessionData
}

// PasskeyService orchestrates WebAuthn ceremonies using injected stores + RP.
type PasskeyService struct {
	users  UserStore
	creds  CredentialStore
	wa     *webauthn.WebAuthn
	pepper string // for email hashing (LOXTU_HASH_PEPPER)

	mu       sync.Mutex
	sessions map[string]*CeremonySession
}

// NewPasskeyService wires RP + ports. wa must be non-nil (composition root).
func NewPasskeyService(users UserStore, creds CredentialStore, wa *webauthn.WebAuthn, pepper string) *PasskeyService {
	return &PasskeyService{
		users:    users,
		creds:    creds,
		wa:       wa,
		pepper:   pepper,
		sessions: make(map[string]*CeremonySession),
	}
}

// NewWebAuthn builds Relying Party config.
func NewWebAuthn(rpid, origin string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rpid,
		RPDisplayName: "LOXTU",
		RPOrigins:     []string{origin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 60 * time.Second},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 120 * time.Second},
		},
	})
}

// ResolveUserID finds users.UserID by email hash via UserStore.
func (s *PasskeyService) ResolveUserID(ctx context.Context, email string) (string, error) {
	emailHash := EmailHashWithPepper(email, s.pepper)
	u, err := s.users.FindByEmailHash(ctx, emailHash)
	if err != nil {
		return "", fmt.Errorf("lookup user: %w", err)
	}
	if u == nil || u.UserID == "" {
		return "", fmt.Errorf("user not found: %s", email)
	}
	return u.UserID, nil
}

// FindOrCreatePasskeyUser resolves user then loads/creates passkey principal.
func (s *PasskeyService) FindOrCreatePasskeyUser(ctx context.Context, email, tenantID string) (*PasskeyUser, error) {
	userID, err := s.ResolveUserID(ctx, email)
	if err != nil {
		return nil, err
	}

	// Try to load existing passkey user by finding any credential for this user
	creds, err := s.creds.FindCredentialsByUserID(ctx, userID)
	if err == nil && len(creds) > 0 {
		return &PasskeyUser{
			UserID:      userID,
			TenantID:    tenantID,
			Email:       email,
			Handle:      nil, // will be loaded from passkey_users table
			Credentials: webauthnCredsFromDomain(creds),
		}, nil
	}

	// Create new passkey user
	handle, err := GenerateHandleWithTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	if err := s.creds.SaveUser(ctx, userID, handle, tenantID); err != nil {
		return nil, fmt.Errorf("save passkey user: %w", err)
	}
	return &PasskeyUser{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		Handle:   handle,
	}, nil
}

// GetUser loads passkey user + credentials by email.
func (s *PasskeyService) GetUser(ctx context.Context, email string) (*PasskeyUser, error) {
	userID, err := s.ResolveUserID(ctx, email)
	if err != nil {
		return nil, err
	}
	creds, err := s.creds.FindCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("no passkey credentials for user %s", userID)
	}
	return &PasskeyUser{
		UserID:      userID,
		Email:       email,
		Credentials: webauthnCredsFromDomain(creds),
	}, nil
}

// SaveCredential persists a credential for the user.
func (s *PasskeyService) SaveCredential(ctx context.Context, userID string, cred *webauthn.Credential) error {
	pc := &PasskeyCredential{
		CredentialID:   cred.ID,
		UserID:         userID,
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		Transports:     transportStrings(cred.Transport),
		AAGUID:         string(cred.Authenticator.AAGUID),
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		CreatedAt:      time.Now(),
	}
	return s.creds.SaveCredential(ctx, pc)
}

// UpdateCredentialSignCount updates sign counter after successful assertion.
func (s *PasskeyService) UpdateCredentialSignCount(ctx context.Context, userID string, kid []byte, newCount uint32) error {
	return s.creds.UpdateSignCount(ctx, userID, kid, newCount)
}

// FindUserByHandle loads user by WebAuthn handle.
func (s *PasskeyService) FindUserByHandle(ctx context.Context, userHandle []byte) (*PasskeyUser, error) {
	user, err := s.creds.FindUserByHandle(ctx, userHandle)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found by handle")
	}
	return user, nil
}

// BeginRegistration starts a registration ceremony.
func (s *PasskeyService) BeginRegistration(ctx context.Context, email, tenantID string) (*protocol.CredentialCreation, string, error) {
	if s.wa == nil {
		return nil, "", fmt.Errorf("webauthn not initialised")
	}
	user, err := s.FindOrCreatePasskeyUser(ctx, email, tenantID)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}
	challenge := session.Challenge
	s.storeSession(challenge, &CeremonySession{
		Challenge:  challenge,
		UserID:     user.UserID,
		UserEmail:  email,
		TenantID:   tenantID,
		UserHandle: user.Handle,
		WASession:  session,
	})
	return options, challenge, nil
}

// FinishRegistration completes registration given parsed response and challenge.
func (s *PasskeyService) FinishRegistration(ctx context.Context, challenge string, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, *PasskeyUser, error) {
	if s.wa == nil {
		return nil, nil, fmt.Errorf("webauthn not initialised")
	}
	cs, err := s.takeSession(challenge)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.GetUser(ctx, cs.UserEmail)
	if err != nil {
		user, err = s.FindOrCreatePasskeyUser(ctx, cs.UserEmail, cs.TenantID)
		if err != nil {
			return nil, nil, err
		}
	}
	// Restore handle from session — must match WebAuthnID() for CreateCredential
	user.Handle = cs.UserHandle
	cred, err := s.wa.CreateCredential(user, *cs.WASession, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("create credential: %w", err)
	}
	if err := s.SaveCredential(ctx, user.UserID, cred); err != nil {
		return nil, nil, err
	}
	user.Credentials = append(user.Credentials, *cred)
	return cred, user, nil
}

// BeginLoginDiscoverable starts a login ceremony without specifying a user.
func (s *PasskeyService) BeginLoginDiscoverable(ctx context.Context, tenantID string) (*protocol.CredentialAssertion, string, error) {
	if s.wa == nil {
		return nil, "", fmt.Errorf("webauthn not initialised")
	}
	options, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("begin discoverable login: %w", err)
	}
	challenge := session.Challenge
	s.storeSession(challenge, &CeremonySession{
		Challenge: challenge,
		UserID:    "",
		UserEmail: "",
		TenantID:  tenantID,
		WASession: session,
	})
	return options, challenge, nil
}

// BeginLogin starts an assertion ceremony.
func (s *PasskeyService) BeginLogin(ctx context.Context, email, tenantID string) (*protocol.CredentialAssertion, string, error) {
	if s.wa == nil {
		return nil, "", fmt.Errorf("webauthn not initialised")
	}
	user, err := s.GetUser(ctx, email)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin login: %w", err)
	}
	challenge := session.Challenge
	s.storeSession(challenge, &CeremonySession{
		Challenge: challenge,
		UserID:    user.UserID,
		UserEmail: email,
		TenantID:  tenantID,
		WASession: session,
	})
	return options, challenge, nil
}

// FinishLogin completes assertion.
func (s *PasskeyService) FinishLogin(ctx context.Context, challenge string, parsed *protocol.ParsedCredentialAssertionData) (*PasskeyUser, *webauthn.Credential, error) {
	if s.wa == nil {
		return nil, nil, fmt.Errorf("webauthn not initialised")
	}
	cs, err := s.takeSession(challenge)
	if err != nil {
		return nil, nil, err
	}

	var user *PasskeyUser
	if cs.UserEmail != "" {
		// Known-user login (email was provided at BeginLogin).
		user, err = s.GetUser(ctx, cs.UserEmail)
		if err != nil {
			return nil, nil, err
		}
		cred, err := s.wa.ValidateLogin(user, *cs.WASession, parsed)
		if err != nil {
			return nil, nil, fmt.Errorf("validate login: %w", err)
		}
		if cred != nil {
			_ = s.UpdateCredentialSignCount(ctx, user.UserID, cred.ID, cred.Authenticator.SignCount)
		}
		return user, cred, nil
	}

	// Discoverable login — resolve user from assertion.rawID (credential kid).
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		cred, findErr := s.creds.FindCredentialByKID(ctx, rawID)
		if findErr == nil && cred != nil {
			pu := &PasskeyUser{
				UserID:   cred.UserID,
				TenantID: cs.TenantID,
			}
			// Load all credentials for this user
			allCreds, _ := s.creds.FindCredentialsByUserID(ctx, cred.UserID)
			pu.Credentials = webauthnCredsFromDomain(allCreds)
			user = pu
			return pu, nil
		}
		// Fallback: try by handle
		u, findErr := s.FindUserByHandle(ctx, userHandle)
		if findErr != nil {
			return nil, findErr
		}
		user = u
		return u, nil
	}
	cred, err := s.wa.ValidateDiscoverableLogin(handler, *cs.WASession, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("validate discoverable login: %w", err)
	}
	if user == nil {
		return nil, nil, fmt.Errorf("user not resolved from discoverable login")
	}
	if cred != nil {
		_ = s.UpdateCredentialSignCount(ctx, user.UserID, cred.ID, cred.Authenticator.SignCount)
	}
	return user, cred, nil
}

func (s *PasskeyService) storeSession(challenge string, data *CeremonySession) {
	s.mu.Lock()
	s.sessions[challenge] = data
	s.mu.Unlock()
}

func (s *PasskeyService) takeSession(challenge string) (*CeremonySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.sessions[challenge]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	delete(s.sessions, challenge)
	return data, nil
}

// Logf is consistent passkey logging.
func Logf(format string, args ...any) {
	log.Printf("[passkey] "+format, args...)
}

// ── helpers ─────────────────────────────────────────────────────────────

func webauthnCredsFromDomain(creds []*PasskeyCredential) []webauthn.Credential {
	var out []webauthn.Credential
	for _, c := range creds {
		out = append(out, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
				AAGUID:    []byte(c.AAGUID),
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
		})
	}
	return out
}

func transportStrings(transports []protocol.AuthenticatorTransport) []string {
	var out []string
	for _, t := range transports {
		out = append(out, string(t))
	}
	return out
}
