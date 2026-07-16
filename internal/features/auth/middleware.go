package auth

import (
	"context"
	"log"
	"net/http"
	"strings"

	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

const (
	CtxEmail      string = "email"
	CtxRole       string = "role"
	CtxEmployeeID string = "employee_id"
	CtxTenantNS   string = "tenant_ns"
)

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
	"/static/",
}

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

// Guard validates access JWT from cookie and injects claims into context.
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

		claims, err := ValidateAccessToken(cookie.Value)
		if err != nil {
			unauthorized(w, r)
			return
		}

		if lc := mw.GetLogCtx(r.Context()); lc != nil {
			lc.Email = mw.MaskEmail(claims.Email)
		}

		ctx := context.WithValue(r.Context(), CtxEmail, claims.Email)
		ctx = context.WithValue(ctx, CtxRole, claims.Role)
		ctx = context.WithValue(ctx, CtxEmployeeID, claims.EmployeeID)
		ctx = context.WithValue(ctx, CtxTenantNS, claims.TenantNS)

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

func GetEmail(r *http.Request) string {
	v, _ := r.Context().Value(CtxEmail).(string)
	return v
}

func GetRole(r *http.Request) string {
	v, _ := r.Context().Value(CtxRole).(string)
	return v
}

func GetEmployeeID(r *http.Request) string {
	v, _ := r.Context().Value(CtxEmployeeID).(string)
	return v
}

func GetTenantNS(r *http.Request) string {
	v, _ := r.Context().Value(CtxTenantNS).(string)
	return v
}