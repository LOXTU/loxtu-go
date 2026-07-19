package identity

import "context"

// ctxKey is a typed string for context.WithValue to avoid collisions.
type ctxKey string

// TenantIDKey is the context key for the resolved tenant identifier.
// Set by Guard from JWT (authenticated) or by handler from email domain (public paths).
const TenantIDKey ctxKey = "tenant_id"

// UserIDHashKey is the context key for user_id_hash (SHA-256 of user UUID).
// Set by Guard from JWT sub claim. Not PII — hash, not raw UUID.
const UserIDHashKey ctxKey = "user_id_hash"

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

// GetUserIDHash safely extracts user_id_hash from context.
func GetUserIDHash(ctx context.Context) string {
	if v := ctx.Value(UserIDHashKey); v != nil {
		if h, ok := v.(string); ok {
			return h
		}
	}
	return ""
}