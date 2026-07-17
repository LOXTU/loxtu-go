// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
)

// ── CSRF ──────────────────────────────────────────────────────────────────

// CSRF generates a token on GET and validates it on POST/PUT/DELETE.
// The token is set as cookie `loxtu_csrf`. Requests must include the token
// in the `X-CSRF-Token` header or `_csrf` form field.
// Public routes and API/JSON requests are skipped.
// ⚠️ HX-Request is NOT bypassed — all POST requests must have a valid token.
func CSRF(publicPaths []string) func(http.Handler) http.Handler {
	var (
		mu     sync.Mutex
		tokens = make(map[string]bool)
	)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Skip public routes
			for _, p := range publicPaths {
				if strings.HasPrefix(path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Skip API/JSON requests only
			if strings.HasPrefix(r.Header.Get("Accept"), "application/json") ||
				r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
				next.ServeHTTP(w, r)
				return
			}

			// GET → set CSRF token cookie
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				token := generateCSRFToken()
				mu.Lock()
				tokens[token] = true
				mu.Unlock()

				http.SetCookie(w, &http.Cookie{
					Name:     "loxtu_csrf",
					Value:    token,
					Path:     "/",
					HttpOnly: false,
					SameSite: http.SameSiteLaxMode,
					Secure:   false,
				})
				next.ServeHTTP(w, r)
				return
			}

			// POST/PUT/DELETE → validate CSRF token
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				token := r.Header.Get("X-CSRF-Token")
				if token == "" {
					token = r.FormValue("_csrf")
				}

				// Read expected token from cookie
				cookie, err := r.Cookie("loxtu_csrf")
				if err != nil || cookie.Value == "" {
					http.Error(w, "CSRF token missing", http.StatusForbidden)
					return
				}

				// Trim spaces to prevent hidden \r / \n issues
				got := strings.TrimSpace(token)
				expected := strings.TrimSpace(cookie.Value)

				mu.Lock()
				valid := tokens[got]
				if valid {
					delete(tokens, got)
				}
				mu.Unlock()

				if !valid {
					log.Printf("[csrf] token not in map: got=%q (len=%d) expected=%q (len=%d)", got, len(got), expected, len(expected))
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}
				if got != expected {
					log.Printf("[csrf] token mismatch: got=%q (len=%d) expected=%q (len=%d)", got, len(got), expected, len(expected))
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}

				// On success, generate a fresh token for next POST (HTMX flow)
				newToken := generateCSRFToken()
				mu.Lock()
				tokens[newToken] = true
				mu.Unlock()
				http.SetCookie(w, &http.Cookie{
					Name:     "loxtu_csrf",
					Value:    newToken,
					Path:     "/",
					HttpOnly: false,
					SameSite: http.SameSiteLaxMode,
					Secure:   false,
				})
			}

			next.ServeHTTP(w, r)
		})
	}
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}