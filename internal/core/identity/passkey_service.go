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
// No http.Request — handlers pass challenge/response data only.
type CeremonySession struct {
	Challenge            string
	UserID               string
	UserEmail            string
	TenantNS             string
	AllowedCredentialIDs [][]byte
	Expires              int64
	UserVerification     string
	WASession            *webauthn.SessionData
}

// PasskeyService orchestrates WebAuthn ceremonies using injected stores + RP.
type PasskeyService struct {
	users UserStore
	creds CredentialStore
	wa    *webauthn.WebAuthn

	mu       sync.Mutex
	sessions map[string]*CeremonySession
}

// NewPasskeyService wires RP + ports. wa must be non-nil (composition root).
func NewPasskeyService(users UserStore, creds CredentialStore, wa *webauthn.WebAuthn) *PasskeyService {
	return &PasskeyService{
		users:    users,
		creds:    creds,
		wa:       wa,
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

// ResolveActorID finds users.id by email hash via UserStore.
func (s *PasskeyService) ResolveActorID(ctx context.Context, email, tenantNS string) (string, error) {
	if tenantNS == "" {
		tenantNS = "public"
	}
	u, err := s.users.FindByEmailHash(ctx, tenantNS, EmailHash(email))
	if err != nil {
		return "", fmt.Errorf("lookup user: %w", err)
	}
	if u == nil || u.ActorID == "" {
		return "", fmt.Errorf("user not found in users table: %s (tenant: %s)", email, tenantNS)
	}
	return u.ActorID, nil
}

// FindOrCreateUser resolves actor then loads/creates passkey principal.
func (s *PasskeyService) FindOrCreateUser(ctx context.Context, email, tenantNS string) (*PasskeyUser, error) {
	if tenantNS == "" {
		tenantNS = "public"
	}

	actorID, err := s.ResolveActorID(ctx, email, tenantNS)
	if err != nil {
		return nil, err
	}

	user, err := s.creds.FindPasskeyUserByActor(ctx, tenantNS, actorID)
	if err == nil && user != nil {
		user.Email = email
		user.TenantNS = tenantNS
		user.ActorID = actorID
		return user, nil
	}

	handle, err := GenerateHandleWithTenant(tenantNS)
	if err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	if err := s.creds.UpsertPasskeyUser(ctx, tenantNS, actorID, email, handle); err != nil {
		return nil, fmt.Errorf("upsert passkey user: %w", err)
	}
	return &PasskeyUser{
		Email:    email,
		TenantNS: tenantNS,
		Handle:   handle,
		ActorID:  actorID,
	}, nil
}

// GetUser loads passkey user + credentials by email.
func (s *PasskeyService) GetUser(ctx context.Context, email, tenantNS string) (*PasskeyUser, error) {
	actorID, err := s.ResolveActorID(ctx, email, tenantNS)
	if err != nil {
		return nil, err
	}
	user, err := s.creds.FindPasskeyUserByActor(ctx, tenantNS, actorID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("passkey user not found: %s", email)
	}
	user.Email = email
	user.TenantNS = tenantNS
	user.ActorID = actorID
	return user, nil
}

// SaveCredential persists a credential for the user's actor.
func (s *PasskeyService) SaveCredential(ctx context.Context, email, tenantNS string, cred *webauthn.Credential) error {
	actorID, err := s.ResolveActorID(ctx, email, tenantNS)
	if err != nil {
		return err
	}
	return s.creds.SaveCredential(ctx, tenantNS, actorID, cred)
}

// UpdateCredentialSignCount updates sign counter after successful assertion.
func (s *PasskeyService) UpdateCredentialSignCount(ctx context.Context, email, tenantNS string, kid []byte, newCount int) error {
	actorID, err := s.ResolveActorID(ctx, email, tenantNS)
	if err != nil {
		return err
	}
	return s.creds.UpdateSignCount(ctx, tenantNS, actorID, kid, newCount)
}

// FindUserByHandle loads user by WebAuthn handle (tenant in handle prefix).
func (s *PasskeyService) FindUserByHandle(ctx context.Context, userHandle []byte) (*PasskeyUser, error) {
	tenantNS, _, err := ParseHandle(userHandle)
	if err != nil {
		tenantNS = "public"
	}
	user, err := s.creds.FindByHandle(ctx, tenantNS, userHandle)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found by handle")
	}
	if user.TenantNS == "" {
		user.TenantNS = tenantNS
	}
	user.Handle = userHandle
	return user, nil
}

// BeginRegistration starts a registration ceremony.
func (s *PasskeyService) BeginRegistration(ctx context.Context, email, tenantNS string) (*protocol.CredentialCreation, string, error) {
	if s.wa == nil {
		return nil, "", fmt.Errorf("webauthn not initialised")
	}
	user, err := s.FindOrCreateUser(ctx, email, tenantNS)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}
	challenge := session.Challenge
	s.storeSession(challenge, &CeremonySession{
		Challenge: challenge,
		UserID:    string(user.Handle),
		UserEmail: email,
		TenantNS:  tenantNS,
		WASession: session,
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
	user, err := s.GetUser(ctx, cs.UserEmail, cs.TenantNS)
	if err != nil {
		user, err = s.FindOrCreateUser(ctx, cs.UserEmail, cs.TenantNS)
		if err != nil {
			return nil, nil, err
		}
	}
	cred, err := s.wa.CreateCredential(user, *cs.WASession, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("create credential: %w", err)
	}
	if err := s.SaveCredential(ctx, cs.UserEmail, cs.TenantNS, cred); err != nil {
		return nil, nil, err
	}
	user.Credentials = append(user.Credentials, *cred)
	return cred, user, nil
}

// BeginLogin starts an assertion ceremony.
func (s *PasskeyService) BeginLogin(ctx context.Context, email, tenantNS string) (*protocol.CredentialAssertion, string, error) {
	if s.wa == nil {
		return nil, "", fmt.Errorf("webauthn not initialised")
	}
	user, err := s.GetUser(ctx, email, tenantNS)
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
		UserID:    string(user.Handle),
		UserEmail: email,
		TenantNS:  tenantNS,
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
		user, err = s.GetUser(ctx, cs.UserEmail, cs.TenantNS)
	} else if len(parsed.Response.UserHandle) > 0 {
		user, err = s.FindUserByHandle(ctx, parsed.Response.UserHandle)
	} else {
		return nil, nil, fmt.Errorf("no user identity for login")
	}
	if err != nil {
		return nil, nil, err
	}

	cred, err := s.wa.ValidateLogin(user, *cs.WASession, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("validate login: %w", err)
	}
	if cred != nil {
		_ = s.UpdateCredentialSignCount(ctx, user.Email, user.TenantNS, cred.ID, int(cred.Authenticator.SignCount))
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

// StoreCeremony / GetCeremony for thin HTTP adapters during migration.
func (s *PasskeyService) StoreCeremony(challenge string, data *CeremonySession) {
	s.storeSession(challenge, data)
}

// GetCeremony returns and consumes a ceremony session.
func (s *PasskeyService) GetCeremony(challenge string) (*CeremonySession, error) {
	return s.takeSession(challenge)
}

// Logf is consistent passkey logging.
func Logf(format string, args ...any) {
	log.Printf("[passkey] "+format, args...)
}
