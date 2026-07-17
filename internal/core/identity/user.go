// Package identity holds domain types and rules for users, sessions, OTP and passkeys.
// No HTTP, templ, SurrealDB or email package imports.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User is the core identity entity (maps to progressive-profiling `users` + profile).
type User struct {
	// ActorID is the full record id, e.g. "users:abc…".
	ActorID string
	// EmailHash is SHA-256 hex of lowercased email (PII isolation at rest).
	EmailHash string
	// TenantNS is the SurrealDB namespace this user belongs to.
	TenantNS string
	// Email is optional enrichment (passkey/profile); never required for minimal OTP user.
	Email string
	// Role is the primary application role (worker, manager, admin).
	Role string
	// Roles is the full role set (HasRole checks Role + Roles).
	Roles []string
	// Skills is capability tags (e.g. ramp, nacelle).
	Skills []string
	// EmployeeID is optional payroll/HR link.
	EmployeeID string
	// IsActive is false for progressive-profiling minimal users until consent/passkey.
	IsActive bool
}

// HasRole reports whether the user holds role (primary Role or Roles list).
func (u *User) HasRole(role string) bool {
	if u == nil || role == "" {
		return false
	}
	if u.Role == role {
		return true
	}
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasSkill reports whether the user has the given skill tag.
func (u *User) HasSkill(skill string) bool {
	if u == nil || skill == "" {
		return false
	}
	for _, s := range u.Skills {
		if s == skill {
			return true
		}
	}
	return false
}

// PasskeyUser is the domain representation of a WebAuthn principal.
// Implements webauthn.User.
type PasskeyUser struct {
	Email       string
	TenantNS    string
	Handle      []byte
	Credentials []webauthn.Credential
	ActorID     string
}

// WebAuthnID returns the opaque user handle (max 64 bytes).
func (u *PasskeyUser) WebAuthnID() []byte { return u.Handle }

// WebAuthnName returns the user's name (email).
func (u *PasskeyUser) WebAuthnName() string { return u.Email }

// WebAuthnDisplayName returns the browser display name.
func (u *PasskeyUser) WebAuthnDisplayName() string { return u.Email }

// WebAuthnCredentials returns registered authenticators.
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// EmailHash returns SHA-256 hex of lowercased email (PII isolation).
func EmailHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// GenerateHandle creates a cryptographically random 64-byte WebAuthn handle.
func GenerateHandle() ([]byte, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	return b, nil
}

// GenerateHandleWithTenant encodes tenantNS as prefix: "tenantNS:base64(32B)".
func GenerateHandleWithTenant(tenantNS string) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return []byte(tenantNS + ":" + encoded), nil
}

// ParseHandle extracts tenantNS and the random portion from a composite handle.
func ParseHandle(handle []byte) (tenantNS string, actualHandle []byte, err error) {
	s := string(handle)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", handle, fmt.Errorf("invalid handle format: missing tenantNS")
	}
	return parts[0], []byte(parts[1]), nil
}
