package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/loxtu/loxtu-go/internal/core/identity"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
)

// OAuthHandler is the HTTP surface for OAuth2 flows.
type OAuthHandler struct {
	oauth  *identity.OAuthService
	tokens *identity.TokenService
}

// NewOAuthHandler constructs an OAuthHandler.
func NewOAuthHandler(oauth *identity.OAuthService, tokens *identity.TokenService) *OAuthHandler {
	return &OAuthHandler{oauth: oauth, tokens: tokens}
}

// Mount registers OAuth routes.
func (h *OAuthHandler) Mount(r chi.Router) {
	r.Get("/auth/oauth/{provider}", h.BeginAuth)
	r.Get("/auth/oauth/{provider}/callback", h.Callback)
	r.Post("/auth/oauth/{provider}/callback", h.Callback) // Apple uses POST
}

// BeginAuth redirects the user to the provider's authorization page.
func (h *OAuthHandler) BeginAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}

	// Resolve tenant from email domain or query param
	tenantID := mw.GetTenantCode(r.Context())
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/dashboard"
	}

	authURL, state, err := h.oauth.BeginAuth(provider, tenantID, redirectURI)
	if err != nil {
		slog.Error("OAuth begin failed", "provider", provider, "err", err)
		http.Error(w, "OAuth not available", http.StatusBadRequest)
		return
	}

	// Store state in a short-lived cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Callback handles the redirect from the provider.
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	// Get code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Apple sends form POST
	if code == "" {
		code = r.FormValue("code")
	}
	if state == "" {
		state = r.FormValue("state")
	}

	if code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	// Validate state cookie
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != state {
		slog.Error("OAuth state mismatch", "provider", provider)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", Path: "/", MaxAge: -1})

	// Complete OAuth flow
	info, userID, err := h.oauth.CompleteAuth(r.Context(), provider, state, code)
	if err != nil {
		slog.Error("OAuth complete failed", "provider", provider, "err", err)
		http.Error(w, "OAuth failed", http.StatusInternalServerError)
		return
	}

	// Resolve tenant from email domain
	tenantID := mw.GetTenantCode(r.Context())
	if tenantID == "" || tenantID == "public" {
		if domain := emailDomain(info.Email); domain != "" {
			// Tenant resolution happens via middleware
			tenantID = mw.GetTenantCode(r.Context())
		}
	}
	if tenantID == "" {
		tenantID = "public"
	}

	// Issue tokens
	pair, err := h.tokens.IssueSession(r.Context(), userID, tenantID, "worker", nil)
	if err != nil {
		slog.Error("OAuth IssueSession failed", "provider", provider, "err", err)
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}

	setAuthCookies(w, pair)
	clearTempAuthCookies(w)

	slog.Info("OAuth login success", "provider", provider, "user_id", userID)

	// Redirect to dashboard or stored redirect
	redirect := "/dashboard"
	if r.URL.Query().Get("redirect_uri") != "" {
		redirect = r.URL.Query().Get("redirect_uri")
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", redirect)
		w.WriteHeader(http.StatusOK)
	} else {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}
}

// GetProviders returns available OAuth providers for the login page.
func (h *OAuthHandler) GetProviders() []string {
	return h.oauth.GetProviders()
}

// PasskeyPresenceFunc is re-exported for use in main.go
var _ = httputil.WriteJSON
