// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"context"
	"net/http"
)

// ── DB Context (Thread-safe, no new connections per request) ────────────────

type dbSessionCtxKey string

const DBSessionCtxKey dbSessionCtxKey = "db_session"

// GetDBSession extracts the scoped DB session info from request context.
func GetDBSession(ctx context.Context) *ContextualNS {
	v, _ := ctx.Value(DBSessionCtxKey).(*ContextualNS)
	return v
}

// ContextualNS carries the target namespace for a request.
// No actual SurrealDB connection is created — we use the shared global pool
// and pass the NS as a parameter.
type ContextualNS struct {
	NS string
}

// DBContext stores the tenant namespace in context.
// ⚠️ No new SurrealDB connections are created per request.
// All queries use the shared global Client pool.
func DBContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantCode := GetTenantCode(r.Context())
		if tenantCode == "" {
			tenantCode = "public"
		}

		ctx := context.WithValue(r.Context(), DBSessionCtxKey, &ContextualNS{NS: tenantCode})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}