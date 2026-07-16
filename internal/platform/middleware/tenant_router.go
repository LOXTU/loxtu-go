// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"github.com/loxtu/loxtu-go/internal/platform/db"
)

type tenantCtxKey string

const TenantCtxKey tenantCtxKey = "tenant_code"

func GetTenantCode(ctx context.Context) string {
	v, _ := ctx.Value(TenantCtxKey).(string)
	return v
}

type preAuthState struct {
	Email    string `json:"email"`
	TenantNS string `json:"tenant_ns"`
}

// TenantRouter resolves the tenant namespace from the request.
//
// Priority order:
//  1. JWT (protected routes) — TenantNS from access token
//  2. pre_auth_state cookie — saved during /auth/otp/send
//  3. POST form "email" — extracts domain, looks up in control_plane
//  4. Fallback — "public"
func TenantRouter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantCode := resolveTenantCode(r)
		ctx := context.WithValue(r.Context(), TenantCtxKey, tenantCode)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func resolveTenantCode(r *http.Request) string {
	// Priority 1: JWT token
	if claims := getJWTClaims(r); claims != nil && claims.TenantNS != "" {
		log.Printf("[tenant] Priority 1 (JWT): NS=%s", claims.TenantNS)
		return claims.TenantNS
	}

	// Priority 2: POST form "email" — domain lookup
	email := r.FormValue("email")
	if email != "" {
		code, err := lookupTenantByEmail(email)
		if err != nil {
			log.Printf("[tenant] Priority 2 lookup error: %v", err)
		}
		if code != "" {
			log.Printf("[tenant] Priority 2 resolved: NS=%s (email=%s)", code, MaskEmail(email))
			return code
		}
		// Явно устанавливаем public, если домен не в whitelist
		log.Printf("[tenant] Priority 2: domain not in whitelist, explicit fallback to public (email=%s)", MaskEmail(email))
		return "public"
	}

	// Priority 3: pre_auth_state cookie (only when no email in form body)
	if state := getPreAuthState(r); state != nil && state.TenantNS != "" {
		log.Printf("[tenant] Priority 3 (pre_auth_state): NS=%s email=%s", state.TenantNS, state.Email)
		return state.TenantNS
	}

	// Priority 4: Fallback — uncomment for debugging
	// log.Printf("[tenant] Priority 4 (fallback): public")
	return "public"
}

func getJWTClaims(r *http.Request) *struct {
	TenantNS string `json:"tenant_ns"`
} {
	if c, err := r.Cookie("loxtu_access"); err == nil && c.Value != "" {
		parts := strings.Split(c.Value, ".")
		if len(parts) == 3 {
			payload := parts[1]
			switch len(payload) % 4 {
			case 2:
				payload += "=="
			case 3:
				payload += "="
			}
			if decoded, err := b64decode(payload); err == nil {
				var claims struct {
					TenantNS string `json:"tenant_ns"`
				}
				if json.Unmarshal(decoded, &claims) == nil && claims.TenantNS != "" {
					return &claims
				}
			}
		}
	}
	return nil
}

func b64decode(s string) ([]byte, error) {
	r := strings.NewReader(s)
	decoder := base64.NewDecoder(base64.RawURLEncoding, r)
	return io.ReadAll(decoder)
}

func getPreAuthState(r *http.Request) *preAuthState {
	if c, err := r.Cookie("pre_auth_state"); err == nil && c.Value != "" {
		decoded, err := urlQueryUnescape(c.Value)
		if err != nil {
			decoded = c.Value
		}
		var state preAuthState
		if json.Unmarshal([]byte(decoded), &state) == nil && state.Email != "" {
			return &state
		}
	}
	return nil
}

func urlQueryUnescape(s string) (string, error) {
	var result []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			high := unhex(s[i+1])
			low := unhex(s[i+2])
			if high >= 0 && low >= 0 {
				result = append(result, byte(high<<4|low))
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result), nil
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// lookupTenantByEmail performs a parameterized query against the control_plane
// tenant table. No string concatenation — uses $domain parameter binding.
func lookupTenantByEmail(email string) (string, error) {
	if email == "" {
		return "", nil
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", fmt.Errorf("parse email: %w", err)
	}
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", nil
	}
	domain := strings.ToLower(strings.TrimSpace(parts[1]))

	// Parameterized query — NO string concatenation
	query := "SELECT code FROM tenant WHERE $domain IN domain_whitelist LIMIT 1"
	vars := map[string]any{
		"domain": domain,
	}

	res, err := db.Query(query, vars)
	if err != nil {
		return "", fmt.Errorf("db query failed: %w", err)
	}

	if len(res) == 0 {
		return "", nil
	}

	// Parse SurrealDB Go SDK response
	results, ok := res[0].Result.([]any)
	if !ok || len(results) == 0 {
		return "", nil
	}

	firstRow, ok := results[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected row type: %T", results[0])
	}

	if code, ok := firstRow["code"].(string); ok {
		return code, nil
	}
	return "", nil
}