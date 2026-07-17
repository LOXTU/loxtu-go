package identity

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// UserStore persists users. Implemented by adapters/persistence/surrealdb.
// Returns domain *User — adapters own DTO mapping (never leak adapter DTO to handlers).
type UserStore interface {
	FindByActorID(ctx context.Context, ns, actorID string) (*User, error)
	FindByEmailHash(ctx context.Context, ns, emailHash string) (*User, error)
	// CreateMinimalUser inserts progressive-profiling row; returns actorID.
	CreateMinimalUser(ctx context.Context, ns, emailHash string) (string, error)
}

// SessionStore manages refresh-token sessions.
type SessionStore interface {
	SaveRefreshToken(ctx context.Context, ns, actorID, tokenHash string, expires time.Time) error
	RevokeAllSessions(ctx context.Context, ns, actorID string) error
	FindSessionByHash(ctx context.Context, ns, tokenHash string) (*Session, error)
}

// CredentialStore persists WebAuthn credentials and passkey_users.
type CredentialStore interface {
	SaveCredential(ctx context.Context, ns, actorID string, cred *webauthn.Credential) error
	FindByHandle(ctx context.Context, ns string, handle []byte) (*PasskeyUser, error)
	UpsertPasskeyUser(ctx context.Context, ns, actorID, email string, handle []byte) error
	FindPasskeyUserByActor(ctx context.Context, ns, actorID string) (*PasskeyUser, error)
	UpdateSignCount(ctx context.Context, ns, actorID string, kid []byte, newCount int) error
}
