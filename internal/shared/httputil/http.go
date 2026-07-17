// Package httputil holds shared HTTP / PII helpers with no framework dependency on features.
package httputil

import (
	"encoding/json"
	"net/http"
	"strings"
)

// MaskEmail masks an email for safe logging: v***v@loxtu.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 2 {
		return local[:1] + "***@" + parts[1]
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + parts[1]
}

// WantsJSON returns true if the request asks for JSON (Accept header or ?format=json).
func WantsJSON(r *http.Request) bool {
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") ||
		strings.Contains(accept, "application/ld+json")
}

// WriteJSON sends a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
