package middleware

import (
	"context"

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