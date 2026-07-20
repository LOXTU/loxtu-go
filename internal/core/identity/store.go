package identity

import (
	"context"
	"time"
)

// UserStore persists users. Implemented by adapters/persistence/surrealdb.
type UserStore interface {
	Create(ctx context.Context, user *User) error
	FindByUserID(ctx context.Context, userID string) (*User, error)
	FindByEmailHash(ctx context.Context, emailHash string) (*User, error)
	FindByUserIDHash(ctx context.Context, hash string) (*User, error)
	Update(ctx context.Context, user *User) error
	Erase(ctx context.Context, userID string) error // crypto-shredding
}

// TenantStore resolves tenants. Implemented by adapters/persistence/surrealdb.
type TenantStore interface {
	GetByTenantID(ctx context.Context, tenantID string) (*Tenant, error)
	ResolveByDomain(ctx context.Context, domain string) (*Tenant, error)
}

// OTPStore persists one-time password codes. KV lookup by user_id_hash.
// SurrealDB document ID: otp_codes:[user_id_hash].
type OTPStore interface {
	// Save creates or replaces an OTP code (UPSERT by user_id_hash).
	Save(ctx context.Context, userIDHash, codeHash string, expiresAt time.Time) error
	// Get retrieves the active OTP code for a user.
	Get(ctx context.Context, userIDHash string) (codeHash string, attempts int, expiresAt time.Time, err error)
	// IncrementAttempts increases the failed attempt counter.
	IncrementAttempts(ctx context.Context, userIDHash string) error
	// Delete removes the OTP record (after successful verification or expiry).
	Delete(ctx context.Context, userIDHash string) error
}

// SessionStore manages refresh-token sessions.
type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	RevokeByUserID(ctx context.Context, userID string) error
	RevokeByTokenHash(ctx context.Context, tokenHash string) error
	CleanupExpired(ctx context.Context) error
}

// CredentialStore persists WebAuthn credentials and passkey_users.
type CredentialStore interface {
	SaveUser(ctx context.Context, userID string, handle []byte, tenantID string) error
	SaveCredential(ctx context.Context, cred *PasskeyCredential) error
	FindCredentialsByUserID(ctx context.Context, userID string) ([]*PasskeyCredential, error)
	FindCredentialByKID(ctx context.Context, kid []byte) (*PasskeyCredential, error)
	FindUserByHandle(ctx context.Context, handle []byte) (*PasskeyUser, error)
	FindHandleByUserID(ctx context.Context, userID string) ([]byte, error)
	UpdateSignCount(ctx context.Context, userID string, kid []byte, newCount uint32) error
}
