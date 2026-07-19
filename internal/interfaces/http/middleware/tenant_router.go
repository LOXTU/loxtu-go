// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strings"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// GetTenantID extracts the tenant_id from context (delegates to identity package).
func GetTenantID(ctx context.Context) string {
	return identity.GetTenantID(ctx)
}

type preAuthState struct {
	Email    string `json:"email"`
	TenantID string `json:"tenant_id"`
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
			log.Printf("[tenant] MIDDLEWARE: Resolved tenant_id=%s domain=%s", tenantID, requestHost(r))
			ctx := context.WithValue(r.Context(), identity.TenantIDKey, tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TenantRouter resolves tenant NS from JWT / Host domain / form-email domain / pre_auth / public.
func TenantRouter(next http.Handler) http.Handler {
	return NewTenantRouter(tenantResolver)(next)
}

func resolveTenantID(r *http.Request, resolver TenantResolver) string {
	// Priority 1: JWT (authenticated requests)
	if claims := getJWTClaims(r); claims != nil && claims.TenantID != "" {
		return claims.TenantID
	}

	// Priority 2: HTTP Host domain (e.g. app.loxtu.com or aerlingus.loxtu.com)
	if host := requestHost(r); host != "" {
		// Prefer full host for whitelist; also try root domain of Host
		if code := lookupDomain(r.Context(), resolver, host); code != "" {
			return code
		}
		if sub := leftmostLabel(host); sub != "" && sub != "www" && sub != "app" {
			// Optional: treat subdomain as direct tenant code without DB hit
			// (only if no whitelist hit above — still fall through if code empty)
		}
	}

	// Priority 3: form email domain (OTP send) — extract domain string only
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

	// Priority 4: pre_auth_state cookie (set after OTP send with known tenant)
	if state := getPreAuthState(r); state != nil && state.TenantID != "" {
		return state.TenantID
	}

	// Priority 5: public
	return "public"
}

func lookupDomain(ctx context.Context, resolver TenantResolver, domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	code, err := resolver.ResolveByDomain(ctx, domain)
	if err != nil {
		log.Printf("[tenant] ResolveByDomain(%s): %v", domain, err)
		return ""
	}
	if code != "" {
		return code
	}
	// Try parent domain: app.loxtu.com → loxtu.com
	if i := strings.IndexByte(domain, '.'); i >= 0 && i < len(domain)-1 {
		parent := domain[i+1:]
		if strings.Contains(parent, ".") {
			code, err = resolver.ResolveByDomain(ctx, parent)
			if err != nil {
				log.Printf("[tenant] ResolveByDomain(%s): %v", parent, err)
				return ""
			}
			return code
		}
	}
	return ""
}

// requestHost returns lowercased Host without port.
func requestHost(r *http.Request) string {
	h := r.Host
	if h == "" {
		h = r.Header.Get("X-Forwarded-Host")
		if i := strings.IndexByte(h, ','); i >= 0 {
			h = h[:i]
		}
	}
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(h)
}

// domainFromEmail extracts the domain part of an email for tenant whitelist lookup only.
// Uses net/mail.ParseAddress exclusively — no raw strings.Split (rejects injection / malformed input).
// Returns "" on any parse or shape failure; caller falls back to public.
func domainFromEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 {
		return ""
	}
	// ParseAddress accepts "Name <user@host>" and bare addr; rejects CRLF / multi-@ garbage.
	addr, err := mail.ParseAddress(email)
	if err != nil || addr == nil || addr.Address == "" {
		return ""
	}
	local, domain, ok := strings.Cut(addr.Address, "@")
	if !ok || local == "" || domain == "" {
		return ""
	}
	// Single @ only — defend against pathologically accepted forms
	if strings.Contains(domain, "@") || strings.ContainsAny(domain, " 	\r\n<>\"") {
		return ""
	}
	// Require real DNS-like domain (label.tld)
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return ""
	}
	return strings.ToLower(domain)
}

func leftmostLabel(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[0]
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
