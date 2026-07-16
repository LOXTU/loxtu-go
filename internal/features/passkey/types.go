// Package passkey handles WebAuthn passkey registration and login.
package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyUser implements the webauthn.User interface for SurrealDB-backed storage.
// Email is used as the primary key (same as in the workers/otp flow).
type PasskeyUser struct {
	Email       string                // user identifier, matches workers.email
	TenantNS    string                // 🔥 НОВОЕ: контекст пользователя (источник истины из БД)
	Handle      []byte                // 64 random bytes — WebAuthnID, NOT the email
	Credentials []webauthn.Credential // registered authenticators
}

// WebAuthnID returns the opaque user handle (max 64 bytes, random).
// Must be stable for the user's lifetime. NOT the application user ID.
func (u *PasskeyUser) WebAuthnID() []byte {
	return u.Handle
}

// WebAuthnName returns the user's display name (email here).
func (u *PasskeyUser) WebAuthnName() string {
	return u.Email
}

// WebAuthnDisplayName returns the user's display name for browser UI.
func (u *PasskeyUser) WebAuthnDisplayName() string {
	return u.Email
}

// WebAuthnCredentials returns the list of registered credentials.
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// ── DTO for DB roundtrips ─────────────────────────────────────────────────

// UserRow mirrors the passkey_users table fields.
type UserRow struct {
	Email  string `json:"email"`
	Handle []byte `json:"handle"`
}

// CredRow mirrors the passkey_credentials table fields.
type CredRow struct {
	Email      string   `json:"email"`
	Kid        []byte   `json:"kid"`        // Credential.ID
	PublicKey  []byte   `json:"public_key"` // CBOR-encoded public key
	SignCount  int      `json:"sign_count"`
	AAGUID     string   `json:"aaguid,omitempty"`
	Transports []string `json:"transports,omitempty"`
}

// SessionRow mirrors the passkey_sessions table fields.
type SessionRow struct {
	Challenge  string `json:"challenge"`
	UserID     string `json:"user_id"`    // email
	ExpiresAt  string `json:"expires_at"` // ISO 8601 datetime
	AllowedIDs string `json:"allowed,omitempty"` // JSON array of allowed credential IDs
}