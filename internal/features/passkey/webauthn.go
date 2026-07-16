// Package passkey handles WebAuthn passkey registration and login.
package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn is the global relying-party instance.
var WebAuthn *webauthn.WebAuthn

// InitWebAuthn creates the Relying Party config.
// Called once at server startup.
// Logs each step for traceability.
func InitWebAuthn(rpid, origin string) error {
	log.Printf("[passkey] Initialising WebAuthn RP — ID: %s, Origin: %s", rpid, origin)

	var err error
	WebAuthn, err = webauthn.New(&webauthn.Config{
		RPID:          rpid,          // domain without scheme/port, e.g. "app.loxtu.com"
		RPDisplayName: "LOXTU",       // human-readable name shown in browser dialog
		RPOrigins:     []string{origin}, // e.g. "https://app.loxtu.com"
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 60 * time.Second},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 120 * time.Second},
		},
	})
	if err != nil {
		return fmt.Errorf("webauthn init: %w", err)
	}

	log.Printf("[passkey] WebAuthn RP initialised successfully")
	return nil
}

// GenerateHandle creates a cryptographically random 64-byte WebAuthn user handle.
func GenerateHandle() ([]byte, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	return b, nil
}

// GenerateHandleWithTenant creates a handle that encodes tenantNS as a prefix.
// Format: "tenantNS:base64(32randomBytes)"
// This allows FindUserByWebAuthnID to extract tenantNS without external context.
func GenerateHandleWithTenant(tenantNS string) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return []byte(tenantNS + ":" + encoded), nil
}

// ParseHandle extracts tenantNS and the actual handle bytes from a composite handle.
func ParseHandle(handle []byte) (tenantNS string, actualHandle []byte, err error) {
	s := string(handle)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", handle, fmt.Errorf("invalid handle format: missing tenantNS")
	}
	return parts[0], []byte(parts[1]), nil
}

// Logf is a helper for consistent passkey logging.
func Logf(format string, args ...interface{}) {
	log.Printf("[passkey] "+format, args...)
}