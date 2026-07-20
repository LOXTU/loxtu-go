package handlers

import (
	"context"
	"strings"

	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
)
// TenantResolver extracts email domain and resolves tenant code via TenantResolver.
// Lives in handlers package (transport layer) — not in core.
type TenantResolver struct {
	tenantRepo mw.TenantResolver
}

// NewTenantResolver constructs a TenantResolver.
func NewTenantResolver(repo mw.TenantResolver) *TenantResolver {
	return &TenantResolver{tenantRepo: repo}
}

// ResolveTenantByEmail extracts the domain from email and resolves tenant code.
// Returns ("", nil) if domain is unknown or email is invalid (caller defaults to "public").
func (r *TenantResolver) ResolveTenantByEmail(ctx context.Context, email string) (string, error) {
	if r == nil || r.tenantRepo == nil {
		return "", nil
	}
	domain := extractDomain(email)
	if domain == "" {
		return "", nil
	}
	code, err := r.tenantRepo.ResolveByDomain(ctx, domain)
	if err != nil || code == "" {
		return "", nil
	}
	return code, nil
}

// extractDomain parses and validates an email address, returning the domain part.
// Canonical implementation — validates both local and domain parts.
func extractDomain(email string) string {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 {
		return ""
	}
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	if !strings.Contains(parts[1], ".") || strings.HasPrefix(parts[1], ".") || strings.HasSuffix(parts[1], ".") {
		return ""
	}
	return strings.ToLower(parts[1])
}