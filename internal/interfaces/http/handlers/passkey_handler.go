package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/loxtu/loxtu-go/internal/core/audit"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
	authtmpl "github.com/loxtu/loxtu-go/internal/interfaces/templates/auth"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
	"github.com/loxtu/loxtu-go/internal/security"
)

// PasskeyHandler is the thin HTTP surface for WebAuthn ceremonies.
type PasskeyHandler struct {
	passkey        *identity.PasskeyService
	tokens         *identity.TokenService
	tenantResolver *TenantResolver // email domain → tenant code
	audit          audit.Store
}

// NewPasskeyHandler constructs PasskeyHandler.
func NewPasskeyHandler(pk *identity.PasskeyService, tokens *identity.TokenService, tenantResolver *TenantResolver, auditStore audit.Store) *PasskeyHandler {
	return &PasskeyHandler{passkey: pk, tokens: tokens, tenantResolver: tenantResolver, audit: auditStore}
}

// Mount registers passkey routes.
func (h *PasskeyHandler) Mount(r chi.Router) {
	r.Post("/auth/passkey/begin", h.BeginRegistration)
	r.Post("/auth/passkey/finish", h.FinishRegistration)
	r.Post("/auth/passkey/skip", h.Skip)
	r.Get("/auth/passkey/register", h.RegisterPage)
	r.Get("/auth/passkey/login/begin", h.BeginLogin)
	r.Post("/auth/passkey/login/finish", h.FinishLogin)
}

func (h *PasskeyHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	identity.Logf("Rendering passkey register page for %s", security.MaskEmail(email))
	templ.Handler(authtmpl.RegisterPage(email)).ServeHTTP(w, r)
}

func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := r.FormValue("email")
	mw.SetLogEmail(r, email)
	if email == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	tenantID := ""
	if h.tenantResolver != nil {
		if id, err := h.tenantResolver.ResolveTenantByEmail(r.Context(), email); err == nil && id != "" {
			tenantID = id
		}
	}
	options, challenge, err := h.passkey.BeginRegistration(r.Context(), email, tenantID)
	if err != nil {
		identity.Logf("ERROR BeginRegistration: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin"})
		return
	}
	_ = challenge
	identity.Logf("Registration options sent for %s", security.MaskEmail(email))
	httputil.WriteJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		identity.Logf("ERROR ParseCredentialCreationResponse: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential"})
		return
	}
	challenge := r.Header.Get("X-WebAuthn-Challenge")
	if challenge == "" {
		challenge = parsed.Response.CollectedClientData.Challenge
	}
	cred, user, err := h.passkey.FinishRegistration(r.Context(), challenge, parsed)
	if err != nil {
		identity.Logf("ERROR FinishRegistration: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = cred
	identity.Logf("Registration complete for %s", security.MaskEmail(user.Email))

	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = "public"
	}

	if h.audit != nil {
		_ = h.audit.LogSecurityEvent(r.Context(), audit.SecurityEvent{
			UserID:      user.UserID,
			TenantID:    tenantID,
			MaskedEmail: security.MaskEmail(user.Email),
			Action:      "passkey.register",
			Status:      "success",
			ClientIP:    mw.GetClientIP(r),
			ReqID:       mw.GetRequestID(r.Context()),
		})
	}

	// Issue tokens after registration
	pair, err := h.tokens.IssueSession(r.Context(), user.UserID, tenantID, "worker", nil)
	if err == nil {
		setAuthCookies(w, pair)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/dashboard"})
}

func (h *PasskeyHandler) Skip(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	mw.SetLogEmail(r, email)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenantID := ""
	if h.tenantResolver != nil {
		if id, err := h.tenantResolver.ResolveTenantByEmail(r.Context(), email); err == nil && id != "" {
			tenantID = id
		}
	}
	identity.Logf("SKIP passkey for %s", security.MaskEmail(email))

	// Find user to get userID
	userID, _ := h.passkey.ResolveUserID(r.Context(), email)

	pair, err := h.tokens.IssueSession(r.Context(), userID, tenantID, "worker", nil)
	if err != nil {
		slog.Error("skip IssueTokens failed", "err", err)
	} else {
		setAuthCookies(w, pair)
	}
	w.Header().Set("HX-Redirect", "/dashboard")
	w.WriteHeader(http.StatusOK)
}

func (h *PasskeyHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		// Discoverable login — no email, tenant from existing JWT or empty
		tenantID := mw.GetTenantID(r.Context())
		options, challenge, err := h.passkey.BeginLoginDiscoverable(r.Context(), tenantID)
		if err != nil {
			identity.Logf("BeginLogin discoverable: no credentials: %v", err)
			httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "no-credentials"})
			return
		}
		_ = challenge
		httputil.WriteJSON(w, http.StatusOK, options)
		return
	}
	tenantID := ""
	if h.tenantResolver != nil {
		if id, err := h.tenantResolver.ResolveTenantByEmail(r.Context(), email); err == nil && id != "" {
			tenantID = id
		}
	}
	options, _, err := h.passkey.BeginLogin(r.Context(), email, tenantID)
	if err != nil {
		identity.Logf("BeginLogin: no credentials for %s: %v", security.MaskEmail(email), err)
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "no-credentials"})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid assertion"})
		return
	}
	challenge := parsed.Response.CollectedClientData.Challenge
	user, _, err := h.passkey.FinishLogin(r.Context(), challenge, parsed)
	if err != nil {
		identity.Logf("ERROR FinishLogin: %v", err)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth failed"})
		return
	}
	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = "public"
	}
	identity.Logf("Login successful for user=%s in tenant=%s", user.UserID, tenantID)
	pair, err := h.tokens.IssueSession(r.Context(), user.UserID, tenantID, "worker", nil)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "token issue"})
		return
	}
	setAuthCookies(w, pair)
	if h.audit != nil {
		_ = h.audit.LogSecurityEvent(r.Context(), audit.SecurityEvent{
			UserID:      user.UserID,
			TenantID:    tenantID,
			MaskedEmail: security.MaskEmail(user.Email),
			Action:      "passkey.login",
			Status:      "success",
			ClientIP:    mw.GetClientIP(r),
			ReqID:       mw.GetRequestID(r.Context()),
		})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/dashboard"})
}

// PasskeyPresenceFunc adapts a function to PasskeyPresence.
type PasskeyPresenceFunc func(ctx context.Context, tenantID, email string) bool

// HasPasskey implements PasskeyPresence.
func (f PasskeyPresenceFunc) HasPasskey(ctx context.Context, tenantID, email string) bool {
	return f(ctx, tenantID, email)
}
