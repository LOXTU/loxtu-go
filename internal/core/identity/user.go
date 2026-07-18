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
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User is the core identity entity (maps to users table v2).
// PII fields are stored encrypted (envelope encryption: DEK encrypted by KEK).
type User struct {
	// Identifiers
	UserID   string // UUID v7, generated in Go
	TenantID string // tenant code (was TenantNS/ActorID)
	Status   string // pending | active | suspended | erased

	// Envelope encryption
	EncryptedDEK []byte // DEK encrypted by KEK, stored per-user

	// PII (encrypted with DEK)
	EmailCiphertext      []byte
	NameCiphertext       []byte
	SurnameCiphertext    []byte
	PhoneCiphertext      []byte
	DOBCiphertext        []byte
	EmployeeIDCiphertext []byte

	// Lookup / display (not encrypted)
	EmailHash       string // SHA-256(lowercase(email) + pepper)
	MaskedEmail     string // "v***y@loxtu.com" for UI/logs
	EmployeeIDHash  string // SHA-256(employee_id + pepper), optional
	Role            string
	Permissions     []string
	Department      string
	Section         string
	Base            string
	Skills          []string
	IsActive        bool

	// Counters
	RegistrationAttempts int
	LoginCount           int
	FailedLoginCount     int

	// Timestamps
	LastLoginAt  *time.Time
	LockedUntil  *time.Time
	HireDate     *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ── PII decryption helpers ──────────────────────────────────────────────

// DecryptEmail decrypts EmailCiphertext using the provided DEK.
func (u *User) DecryptEmail(dek []byte) (string, error) {
	if len(u.EmailCiphertext) == 0 {
		return "", nil
	}
	return decryptPIICompat(u.EmailCiphertext, dek)
}

// DecryptName decrypts NameCiphertext using the provided DEK.
func (u *User) DecryptName(dek []byte) (string, error) {
	if len(u.NameCiphertext) == 0 {
		return "", nil
	}
	return decryptPIICompat(u.NameCiphertext, dek)
}

// DecryptSurname decrypts SurnameCiphertext using the provided DEK.
func (u *User) DecryptSurname(dek []byte) (string, error) {
	if len(u.SurnameCiphertext) == 0 {
		return "", nil
	}
	return decryptPIICompat(u.SurnameCiphertext, dek)
}

// MaskedEmailOrCompute returns MaskedEmail if set, otherwise computes it
// from the decrypted email. Returns "***" if neither available.
func (u *User) MaskedEmailOrCompute(dek []byte) string {
	if u.MaskedEmail != "" {
		return u.MaskedEmail
	}
	email, err := u.DecryptEmail(dek)
	if err != nil || email == "" {
		return "***"
	}
	return MaskEmailString(email)
}

// ── Role / permission helpers ───────────────────────────────────────────

// HasRole reports whether the user holds the given role.
func (u *User) HasRole(role string) bool {
	if u == nil || role == "" {
		return false
	}
	return u.Role == role
}

// HasPermission reports whether the user has the given permission.
func (u *User) HasPermission(perm string) bool {
	if u == nil || perm == "" {
		return false
	}
	for _, p := range u.Permissions {
		if p == perm {
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

// ── PasskeyUser (WebAuthn principal) ────────────────────────────────────

// PasskeyUser is the domain representation of a WebAuthn principal.
// Implements webauthn.User.
type PasskeyUser struct {
	UserID      string // UUID v7 (was ActorID)
	TenantID    string // (was TenantNS)
	Email       string // plain email for WebAuthn display (not stored in users table)
	Handle      []byte
	Credentials []webauthn.Credential
}

// WebAuthnID returns the opaque user handle (max 64 bytes).
func (u *PasskeyUser) WebAuthnID() []byte { return u.Handle }

// WebAuthnName returns the user's name (email).
func (u *PasskeyUser) WebAuthnName() string { return u.Email }

// WebAuthnDisplayName returns the browser display name.
func (u *PasskeyUser) WebAuthnDisplayName() string { return u.Email }

// WebAuthnCredentials returns registered authenticators.
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// ── PasskeyCredential ───────────────────────────────────────────────────

// PasskeyCredential represents a stored WebAuthn credential.
type PasskeyCredential struct {
	CredentialID []byte    // kid
	UserID       string    // UUID v7
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	AAGUID       string
	BackupEligible bool
	BackupState    bool
	CreatedAt    time.Time
}

// ── Standalone helpers ──────────────────────────────────────────────────

// EmailHash returns SHA-256(lowercase(email)) without pepper.
// Deprecated: use EmailHashWithPepper for new code.
func EmailHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// EmailHashWithPepper returns SHA-256(lowercase(email) + pepper).
func EmailHashWithPepper(email, pepper string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email)) + pepper))
	return hex.EncodeToString(sum[:])
}

// MaskEmailString returns "v***y@loxtu.com" for UI/logs.
func MaskEmailString(email string) string {
	parts := strings.SplitN(strings.TrimSpace(email), "@", 2)
	if len(parts) != 2 || len(parts[0]) == 0 {
		return "***"
	}
	local := parts[0]
	if len(local) <= 2 {
		return local[:1] + "***@" + parts[1]
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + parts[1]
}

// GenerateHandle creates a cryptographically random 64-byte WebAuthn handle.
func GenerateHandle() ([]byte, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	return b, nil
}

// GenerateHandleWithTenant encodes tenantID as prefix: "tenantID:base64(32B)".
func GenerateHandleWithTenant(tenantID string) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return []byte(tenantID + ":" + encoded), nil
}

// ParseHandle extracts tenantID and the random portion from a composite handle.
func ParseHandle(handle []byte) (tenantID string, actualHandle []byte, err error) {
	s := string(handle)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", handle, fmt.Errorf("invalid handle format: missing tenantID")
	}
	return parts[0], []byte(parts[1]), nil
}

// DecryptPIIFn is wired by composition root (main) to security.DecryptPII.
// Avoids importing security in core (no reverse dependency).
var DecryptPIIFn func(ciphertext, dek []byte) (string, error)

// decryptPIICompat calls the wired decrypt function.
func decryptPIICompat(ciphertext, dek []byte) (string, error) {
	if DecryptPIIFn != nil {
		return DecryptPIIFn(ciphertext, dek)
	}
	return "", fmt.Errorf("decryptPIICompat: not wired — composition root must set identity.DecryptPIFn")
}
