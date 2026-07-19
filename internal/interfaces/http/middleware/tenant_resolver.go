package middleware

import (
	"context"
	"net/mail"
	"strings"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// TenantResolver maps an HTTP / email domain to a SurrealDB tenant namespace code.
// Middleware never imports DB drivers — adapters implement this port.
//
// Resolve by **domain** (Host header or email domain), never by full email identity.
// Guard/session may run before the user is authenticated.
type TenantResolver interface {
	// ResolveByDomain returns tenant code for domain (e.g. "aerlingus.com"),
	// or "" if not in whitelist (caller treats "" as public).
	// Error only on infrastructure failure.
	ResolveByDomain(ctx context.Context, domain string) (tenantCode string, err error)
}

// TenantResolverFunc adapts a function to TenantResolver.
type TenantResolverFunc func(ctx context.Context, domain string) (string, error)

// ResolveByDomain implements TenantResolver.
func (f TenantResolverFunc) ResolveByDomain(ctx context.Context, domain string) (string, error) {
	return f(ctx, domain)
}

// GetTenantID delegates to identity.GetTenantID.
func GetTenantID(ctx context.Context) string { return identity.GetTenantID(ctx) }

// GetUserIDHash delegates to identity.GetUserIDHash.
func GetUserIDHash(ctx context.Context) string { return identity.GetUserIDHash(ctx) }

// tenantResolver is package-level for handler use (ResolveTenantByEmail).
var tenantResolver TenantResolver

func init() { tenantResolver = noopResolver{} }

// SetTenantResolver injects domain→tenant lookup (called from main at startup).
func SetTenantResolver(r TenantResolver) {
	if r == nil {
		tenantResolver = noopResolver{}
		return
	}
	tenantResolver = r
}

// ResolveTenantByEmail resolves tenant code from an email address via the
// configured resolver. Returns "" on any error or unknown domain.
func ResolveTenantByEmail(ctx context.Context, email string) string {
	domain := domainFromEmail(email)
	if domain == "" {
		return ""
	}
	code, err := tenantResolver.ResolveByDomain(ctx, domain)
	if err != nil || code == "" {
		return ""
	}
	return code
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

// noopResolver always returns empty (→ public fallback).
type noopResolver struct{}

func (noopResolver) ResolveByDomain(context.Context, string) (string, error) { return "", nil }