package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
)

// Claim keys in context (typed string keys scoped to handlers package).
type authCtxKey string

const (
	ctxEmail      authCtxKey = "email"
	ctxRole       authCtxKey = "role"
	ctxEmployeeID authCtxKey = "employee_id"
)

// PublicPaths skip Guard authentication.
var PublicPaths = []string{
	"/health",
	"/auth/otp/send",
	"/auth/otp/verify",
	"/auth/passkey/login/begin",
	"/auth/passkey/login/finish",
	"/auth/passkey/begin",
	"/auth/passkey/finish",
	"/auth/passkey/skip",
	"/auth/passkey/register",
	"/auth/refresh",
	"/auth/logout",
	"/auth/consent",
	"/static/",
}

// IsPublicPath reports whether path is open.
func IsPublicPath(path string) bool {
	for _, p := range PublicPaths {
		if p == path {
			return true
		}
		if strings.HasSuffix(p, "/") && strings.HasPrefix(path, p) {
			return true
		}
	}
	return path == "/"
}

// Guard validates access JWT and enforces tenant match with TenantRouter.
func Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if IsPublicPath(path) {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("[guard] checking token for %s", path)

		cookie, err := r.Cookie("loxtu_access")
		if err != nil {
			unauthorized(w, r)
			return
		}
		claims, err := identity.ValidateAccessToken(cookie.Value)
		if err != nil {
			unauthorized(w, r)
			return
		}

		routerTenant := mw.GetTenantCode(r.Context())
		if claims.TenantNS != "" && routerTenant != "" && claims.TenantNS != routerTenant {
			log.Printf("[guard] TENANT MISMATCH: JWT=%s Router=%s — blocking", claims.TenantNS, routerTenant)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if lc := mw.GetLogCtx(r.Context()); lc != nil {
			lc.Email = httputil.MaskEmail(claims.Email)
			lc.TenantID = claims.TenantNS
		}

		ctx := context.WithValue(r.Context(), ctxEmail, claims.Email)
		ctx = context.WithValue(ctx, ctxRole, claims.Role)
		ctx = context.WithValue(ctx, ctxEmployeeID, claims.EmployeeID)

		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GetEmail returns email claim from context (after Guard).
func GetEmail(r *http.Request) string {
	v, _ := r.Context().Value(ctxEmail).(string)
	return v
}

// GetRole returns role claim from context.
func GetRole(r *http.Request) string {
	v, _ := r.Context().Value(ctxRole).(string)
	return v
}

// GetEmployeeID returns employee_id claim from context.
func GetEmployeeID(r *http.Request) string {
	v, _ := r.Context().Value(ctxEmployeeID).(string)
	return v
}
