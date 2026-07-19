// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// GetTenantID extracts the tenant_id from context (delegates to identity package).
func GetTenantID(ctx context.Context) string {
	return identity.GetTenantID(ctx)
}

// tenantResolver is package-level injectable for composition root (M5).
// Defaults to noop → always "public" unless SetTenantResolver is called.
var tenantResolver TenantResolver = noopResolver{}

// SetTenantResolver injects domain→tenant lookup (from main). Safe at startup before Serve.
func SetTenantResolver(r TenantResolver) {
	if r == nil {
		tenantResolver = noopResolver{}
		return
	}
	tenantResolver = r
}

// NewTenantRouter returns middleware with an explicit resolver (preferred over global).
func NewTenantRouter(resolver TenantResolver) func(http.Handler) http.Handler {
	if resolver == nil {
		resolver = noopResolver{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := resolveTenantID(r, resolver)
			log.Printf("[tenant] MIDDLEWARE: Resolved tenant_id=%s", tenantID)
			ctx := context.WithValue(r.Context(), identity.TenantIDKey, tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TenantRouter resolves tenant NS from email domain (JWT / form / query / public).
func TenantRouter(next http.Handler) http.Handler {
	return NewTenantRouter(tenantResolver)(next)
}

// resolveTenantID determines tenant ONLY from email domain — NEVER from HTTP Host header.
func resolveTenantID(r *http.Request, resolver TenantResolver) string {
	// Priority 1: JWT (authenticated requests)
	if claims := getJWTClaims(r); claims != nil && claims.TenantID != "" {
		return claims.TenantID
	}

	// Priority 2: form email domain (POST: OTP send, passkey, consent)
	if email := r.FormValue("email"); email != "" {
		if domain := domainFromEmail(email); domain != "" {
			code, err := resolver.ResolveByDomain(r.Context(), domain)
			if err != nil {
				log.Printf("[tenant] domain lookup error: %v", err)
			}
			if code != "" {
				return code
			}
			return "public"
		}
	}

	// Priority 3: URL query param email (GET: passkey login/register pages)
	if email := r.URL.Query().Get("email"); email != "" {
		if domain := domainFromEmail(email); domain != "" {
			code, err := resolver.ResolveByDomain(r.Context(), domain)
			if err == nil && code != "" {
				return code
			}
		}
	}

	// Priority 4: public (no email means unauthenticated, e.g. health check)
	return "public"
}

// domainFromEmail extracts the domain part of an email for tenant whitelist lookup only.
// Uses net/mail.ParseAddress exclusively — no raw strings.Split (rejects injection / malformed input).
// Returns "" on any parse or shape failure; caller falls back to public.
func domainFromEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 {
		return ""
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr == nil || addr.Address == "" {
		return ""
	}
	local, domain, ok := strings.Cut(addr.Address, "@")
	if !ok || local == "" || domain == "" {
		return ""
	}
	if strings.Contains(domain, "@") || strings.ContainsAny(domain, " \t\r\n<>\"") {
		return ""
	}
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return ""
	}
	return strings.ToLower(domain)
}

func getJWTClaims(r *http.Request) *struct {
	TenantID string `json:"tenant_id"`
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
					TenantID string `json:"tenant_id"`
				}
				if json.Unmarshal(decoded, &claims) == nil && claims.TenantID != "" {
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