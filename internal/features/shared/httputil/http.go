package httputil

import (
	"encoding/json"
	"net/http"
	"strings"
)

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
	json.NewEncoder(w).Encode(v)
}