package identity

import "context"

// ctxKey is a typed string for context.WithValue to avoid collisions.
type ctxKey string

// TenantIDKey is the context key for the resolved tenant identifier.
// Used by middleware (to set) and pool (to read) — no cross-layer import.
const TenantIDKey ctxKey = "tenant_id"

// GetTenantID safely extracts the tenant_id from context.
// Returns "" if not set or not a string.
func GetTenantID(ctx context.Context) string {
	if v := ctx.Value(TenantIDKey); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}