// Package passkey handles WebAuthn passkey registration and login.
package passkey

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/surrealdb/surrealdb.go/pkg/models"

	"github.com/loxtu/loxtu-go/internal/platform/db"
	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

// ── In-memory store (fallback) ──
// Глобальный флаг dbUnavailable удален, чтобы одна ошибка не ломала весь сервер.

var (
	mu           sync.RWMutex
	userStore    = make(map[string]*PasskeyUser)          // email → user
	credStore    = make(map[string][]webauthn.Credential) // email → credentials
	sessionStore = make(map[string]*SessionData)          // challenge → session
)

type SessionData struct {
	Challenge            string
	UserID               string // WebAuthn handle
	UserEmail            string // email for redirect/cookie
	TenantNS             string // tenant namespace for credential lookup
	AllowedCredentialIDs [][]byte
	Expires              int64
	UserVerification     string
	CredParams           []protocol.CredentialParameter
}

// ── Helpers ────────────────────────────────────────────────────────────────

// actorRecord converts a "users:xyz" string to a *models.RecordID pointer.
func actorRecord(id string) *models.RecordID {
	return db.GetRecordID(id)
}

// resolveActorID looks up the user's record ID from the users table by email and tenant.
func resolveActorID(email, tenantNS string) (string, error) {
	if tenantNS == "" {
		tenantNS = "public"
	}
	emailHash := db.EmailHash(email)
	Logf("resolveActorID DEBUG: searching for email_hash=%s in tenantNS=%s", emailHash, tenantNS)

	results, err := db.QueryCtx(context.Background(), tenantNS, tenantNS,
		"SELECT id FROM users WHERE email_hash = $hash LIMIT 1",
		map[string]any{"hash": emailHash},
	)
	if err != nil {
		return "", fmt.Errorf("lookup user: %w", err)
	}
	if len(results) == 0 {
		return "", fmt.Errorf("user not found in users table: %s (tenant: %s)", email, tenantNS)
	}

	switch r := results[0].Result.(type) {
	case map[string]any:
		return db.FormatRecordID(r["id"]), nil
	case []any:
		if len(r) > 0 {
			if row, ok := r[0].(map[string]any); ok {
				return db.FormatRecordID(row["id"]), nil
			}
		}
	}
	return "", fmt.Errorf("user not found in users table: %s", email)
}

// ── DB-backed ─────────────────────────────────────────────────────────────

// FindOrCreateUser looks up a passkey user by email, or creates one with a new handle.
func FindOrCreateUser(email, tenantID string) (*PasskeyUser, error) {
	if tenantID == "" {
		tenantID = "public"
	}
	Logf("FindOrCreateUser: %s (tenant=%s)", mw.MaskEmail(email), tenantID)

	// Проверяем наличие БД напрямую, без глобального флага
	if db.DB != nil {
		// Resolve actor_id first — fail if user doesn't exist
		actorID, err := resolveActorID(email, tenantID)
		if err != nil {
			Logf("DB resolveActorID failed for %s: %v. Falling back to memory for this user only.", mw.MaskEmail(email), err)
			return findOrCreateInMem(email, tenantID)
		}

		user, err := queryUser(actorID, tenantID)
		if err == nil && user != nil {
			return user, nil
		}

		// Create new passkey user
		handle, err := GenerateHandleWithTenant(tenantID)
		if err != nil {
			return nil, fmt.Errorf("generate handle: %w", err)
		}
		_, err = db.QueryCtx(context.Background(), tenantID, tenantID,
			"UPSERT passkey_users CONTENT { actor_id: $actor, handle: $handle, email: $email }",
			map[string]any{"actor": actorRecord(actorID), "handle": handle, "email": email},
		)
		if err != nil {
			Logf("DB create user failed, fallback to mem: %v", err)
			return findOrCreateInMem(email, tenantID)
		}
		Logf("User created in DB: %s", mw.MaskEmail(email))
		return &PasskeyUser{Email: email, Handle: handle}, nil
	}
	return findOrCreateInMem(email, tenantID)
}

// queryUser looks up a passkey user by actor_id and tenant.
func queryUser(actorID, tenantNS string) (*PasskeyUser, error) {
	if actorID == "" {
		return nil, fmt.Errorf("actor_id is empty")
	}
	results, err := db.QueryCtx(context.Background(), tenantNS, tenantNS, "SELECT * FROM passkey_users WHERE actor_id = $actor LIMIT 1", map[string]any{"actor": actorRecord(actorID)})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("user not found: %s", actorID)
	}
	rows, ok := results[0].Result.([]any)
	if !ok || len(rows) == 0 {
		return nil, fmt.Errorf("no rows")
	}
	rm, ok := rows[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", rows[0])
	}
	var handle []byte
	switch h := rm["handle"].(type) {
	case []byte:
		handle = h
	case string:
		handle = []byte(h)
	}
	user := &PasskeyUser{Handle: handle}

	creds, err := queryCredentials(actorID, tenantNS)
	if err == nil {
		user.Credentials = creds
	}
	return user, nil
}

// queryCredentials fetches all passkey credentials for a user by actor_id and tenant.
func queryCredentials(actorID, tenantNS string) ([]webauthn.Credential, error) {
	if actorID == "" {
		return nil, nil
	}
	results, err := db.QueryCtx(context.Background(), tenantNS, tenantNS,
		"SELECT * FROM passkey_credentials WHERE actor_id = $actor",
		map[string]any{"actor": actorRecord(actorID)})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	rows, ok := results[0].Result.([]any)
	if !ok {
		return nil, nil
	}

	var creds []webauthn.Credential
	for _, r := range rows {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		c := webauthn.Credential{}

		// Устойчивое извлечение kid
		switch k := rm["kid"].(type) {
		case []byte:
			c.ID = k
		case string:
			c.ID = []byte(k)
		}

		// Устойчивое извлечение public_key
		switch pk := rm["public_key"].(type) {
		case []byte:
			c.PublicKey = pk
		case string:
			c.PublicKey = []byte(pk)
		}

		switch sc := rm["sign_count"].(type) {
		case float64:
			c.Authenticator.SignCount = uint32(sc)
		case int64:
			c.Authenticator.SignCount = uint32(sc)
		case int:
			c.Authenticator.SignCount = uint32(sc)
		}

		if be, ok := rm["backup_eligible"].(bool); ok {
			c.Flags.BackupEligible = be
		}
		if bs, ok := rm["backup_state"].(bool); ok {
			c.Flags.BackupState = bs
		}
		if trans, ok := rm["transports"].([]any); ok {
			for _, t := range trans {
				if ts, ok := t.(string); ok {
					c.Transport = append(c.Transport, protocol.AuthenticatorTransport(ts))
				}
			}
		}
		creds = append(creds, c)
	}
	return creds, nil
}

var _ protocol.AuthenticatorTransport

// ── In-memory fallback ────────────────────────────────────────────────────

func findOrCreateInMem(email, tenantID string) (*PasskeyUser, error) {
	mu.RLock()
	user, ok := userStore[email]
	mu.RUnlock()
	if ok {
		return user, nil
	}
	handle, err := GenerateHandleWithTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("create handle: %w", err)
	}
	user = &PasskeyUser{Email: email, Handle: handle}
	mu.Lock()
	userStore[email] = user
	mu.Unlock()
	Logf("User created (mem): %s", mw.MaskEmail(email))
	return user, nil
}

// GetUser returns a stored user by email.
func GetUser(email, tenantID string) (*PasskeyUser, error) {
	if db.DB != nil {
		actorID, err := resolveActorID(email, tenantID)
		if err == nil {
			user, err := queryUser(actorID, tenantID)
			if err == nil && user != nil {
				return user, nil
			}
		}
		Logf("DB GetUser failed, trying mem: %v", err)
	}
	mu.RLock()
	user, ok := userStore[email]
	creds := credStore[email]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("passkey user not found: %s", email)
	}
	user.Credentials = creds
	return user, nil
}

// SaveCredential persists a credential. Requires a valid actor_id from users table.
func SaveCredential(email, tenantID string, cred *webauthn.Credential) error {
	Logf("SaveCredential: %s", mw.MaskEmail(email))

	if db.DB != nil {
		// Resolve actor_id — fail if user doesn't exist
		actorID, err := resolveActorID(email, tenantID)
		if err != nil {
			Logf("DB save failed: %v. Falling back to memory for this user only.", err)
			mu.Lock()
			credStore[email] = append(credStore[email], *cred)
			mu.Unlock()
			return nil
		}

		_, err = db.QueryCtx(context.Background(), tenantID, tenantID,
			"DELETE passkey_credentials WHERE kid = $kid AND actor_id = $actor; CREATE passkey_credentials SET actor_id = $actor, kid = $kid, public_key = $pk, sign_count = $sc, transports = $trans, backup_eligible = $be, backup_state = $bs",
			map[string]any{
				"actor":  actorRecord(actorID),
				"kid":    cred.ID,
				"pk":     cred.PublicKey,
				"sc":     int(cred.Authenticator.SignCount),
				"trans":  cred.Transport,
				"be":     cred.Flags.BackupEligible,
				"bs":     cred.Flags.BackupState,
			},
		)
		if err != nil {
			Logf("DB save failed, fallback to mem: %v", err)
			mu.Lock()
			credStore[email] = append(credStore[email], *cred)
			mu.Unlock()
			return nil
		} else {
			Logf("Credential saved to DB for %s", mw.MaskEmail(email))
			return nil
		}
	}
	mu.Lock()
	credStore[email] = append(credStore[email], *cred)
	mu.Unlock()
	return nil
}

// UpdateCredentialSignCount updates the sign count after login.
func UpdateCredentialSignCount(email string, kid []byte, newCount int, tenantID string) error {
	if db.DB != nil {
		actorID, err := resolveActorID(email, tenantID)
		if err != nil {
			return fmt.Errorf("resolve actor: %w", err)
		}
		_, err = db.QueryCtx(context.Background(), tenantID, tenantID,
			"UPDATE passkey_credentials SET sign_count = $sc WHERE actor_id = $actor AND kid = $kid",
			map[string]any{"actor": actorRecord(actorID), "kid": kid, "sc": newCount},
		)
		if err == nil {
			return nil
		}
		Logf("DB update sign count failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range credStore[email] {
		if string(credStore[email][i].ID) == string(kid) {
			credStore[email][i].Authenticator.SignCount = uint32(newCount)
			return nil
		}
	}
	return fmt.Errorf("credential not found for %s", email)
}

// FindUserByWebAuthnID finds a user by their WebAuthn handle.
func FindUserByWebAuthnID(rawID, userHandle []byte, _ string) (webauthn.User, error) {
	tenantNS, _, err := ParseHandle(userHandle)
	if err != nil {
		tenantNS = "public" // Fallback
	}

	if db.DB != nil {
		// Мы уже запрашиваем email здесь
		results, err := db.QueryCtx(context.Background(), tenantNS, tenantNS,
			"SELECT actor_id, handle, email FROM passkey_users WHERE handle = $handle LIMIT 1",
			map[string]any{"handle": userHandle})

		if err == nil && len(results) > 0 {
			if rows, ok := results[0].Result.([]any); ok && len(rows) > 0 {
				if rm, ok := rows[0].(map[string]any); ok {
					// 1. Получаем actor_id
					actorID := db.FormatRecordID(rm["actor_id"])
					if actorID == "" {
						Logf("Failed to format actor_id: %T %v", rm["actor_id"], rm["actor_id"])
					}

					// 2. БЕРЕМ EMAIL ПРЯМО ОТСЮДА! (Удален лишний запрос к таблице users)
					email, _ := rm["email"].(string)

					// 3. 🔥 ВОЗВРАЩАЕМ ПОЛЬЗОВАТЕЛЯ С TenantNS (источник истины)
					user := &PasskeyUser{
						Email:    email,
						TenantNS: tenantNS, // <-- КЛЮЧЕВОЕ ПОЛЕ
						Handle:   userHandle,
					}
					
					creds, err := queryCredentials(actorID, tenantNS)
					if err != nil {
						Logf("queryCredentials error: %v", err)
					} else {
						Logf("Found user %s with %d credentials in NS=%s", email, len(creds), tenantNS)
					}
					user.Credentials = creds
					return user, nil
				}
			}
		}
		Logf("DB FindUserByWebAuthnID failed, trying mem: %v", err)
	}

	// Fallback to memory
	mu.RLock()
	defer mu.RUnlock()
	for _, u := range userStore {
		if string(u.Handle) == string(userHandle) {
			u.Credentials = credStore[u.Email]
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found by handle")
}

// StoreSession saves a WebAuthn session challenge in memory.
func StoreSession(challenge string, data *SessionData) error {
	Logf("StoreSession: %s...", challenge[:8])
	mu.Lock()
	sessionStore[challenge] = data
	mu.Unlock()
	return nil
}

// GetSession retrieves and deletes a WebAuthn session (single-use).
func GetSession(challenge string) (*SessionData, error) {
	mu.Lock()
	defer mu.Unlock()
	data, ok := sessionStore[challenge]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	delete(sessionStore, challenge)
	return data, nil
}