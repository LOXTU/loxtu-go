// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"net/http"
	"strings"
)

// ── Security Headers ──────────────────────────────────────────────────────

// SecurityHeaders sets HTTP security headers on every response.
// Skips /static/* to avoid breaking CSS/JS loading.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip static files — CSP would break external font/asset loading
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Content-Security-Policy
		csp := []string{
			"default-src 'self'",
			"script-src 'self' https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'",
			"style-src 'self' https://fonts.googleapis.com https://api.fontshare.com 'unsafe-inline'",
			"font-src 'self' https://fonts.gstatic.com https://api.fontshare.com https:",
			"img-src 'self' data:",
			"connect-src 'self' ws://localhost:* http://localhost:*",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		}
		w.Header().Set("Content-Security-Policy", join(csp, "; "))

		// HSTS — only on TLS (detect by checking if request came through proxy with X-Forwarded-Proto)
		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r)
	})
}

func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}
