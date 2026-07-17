package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/loxtu/loxtu-go/internal/core/audit"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
	authtmpl "github.com/loxtu/loxtu-go/internal/interfaces/templates/auth"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
)

// PasskeyHandler is the thin HTTP surface for WebAuthn ceremonies.
type PasskeyHandler struct {
	passkey *identity.PasskeyService
	tokens  *identity.TokenService
	audit   audit.Store
}

// NewPasskeyHandler constructs PasskeyHandler.
func NewPasskeyHandler(pk *identity.PasskeyService, tokens *identity.TokenService, auditStore audit.Store) *PasskeyHandler {
	return &PasskeyHandler{passkey: pk, tokens: tokens, audit: auditStore}
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
		if c, err := r.Cookie("loxtu_email"); err == nil {
			email = c.Value
		}
	}
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	identity.Logf("Rendering passkey register page for %s", httputil.MaskEmail(email))
	templ.Handler(authtmpl.RegisterPage(email)).ServeHTTP(w, r)
}

func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := r.FormValue("email")
	if email == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	tenantNS := mw.GetTenantCode(r.Context())
	options, challenge, err := h.passkey.BeginRegistration(r.Context(), email, tenantNS)
	if err != nil {
		identity.Logf("ERROR BeginRegistration: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin"})
		return
	}
	_ = challenge
	identity.Logf("Registration options sent for %s", httputil.MaskEmail(email))
	httputil.WriteJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		identity.Logf("ERROR ParseCredentialCreationResponse: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential"})
		return
	}
	// Challenge is store-keyed; client data carries the same challenge the RP created.
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
	identity.Logf("Registration complete for %s", httputil.MaskEmail(user.Email))
	if h.audit != nil {
		_ = h.audit.LogSecurityEvent(r.Context(), audit.SecurityEvent{
			ActorID: user.ActorID, ActorEmailMasked: httputil.MaskEmail(user.Email),
			Action: "passkey.register", Status: "success",
			ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
		})
	}
	// Issue tokens after registration
	tenantNS := user.TenantNS
	if tenantNS == "" {
		tenantNS = mw.GetTenantCode(r.Context())
	}
	pair, err := h.tokens.IssueSession(r.Context(), user.Email, tenantNS, "", "worker")
	if err == nil {
		setAuthCookies(w, pair)
		http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: user.Email, Path: "/", MaxAge: 3600})
		http.SetCookie(w, &http.Cookie{
			Name: "loxtu_tenant", Value: tenantNS,
			Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		clearTempAuthCookies(w)
		}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/dashboard"})
}

func (h *PasskeyHandler) Skip(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	if email == "" {
		if c, err := r.Cookie("loxtu_email"); err == nil {
			email = c.Value
		}
	}
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenantNS := mw.GetTenantCode(r.Context())
	identity.Logf("SKIP passkey for %s", httputil.MaskEmail(email))
	pair, err := h.tokens.IssueSession(r.Context(), email, tenantNS, "", "worker")
	if err != nil {
		log.Printf("[passkey] skip IssueTokens: %v", err)
	} else {
		setAuthCookies(w, pair)
		http.SetCookie(w, &http.Cookie{
			Name: "loxtu_tenant", Value: tenantNS,
			Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	clearTempAuthCookies(w)
	// HTMX: redirect to dashboard via HX-Redirect header (SPA navigation).
	w.Header().Set("HX-Redirect", "/dashboard")
	w.WriteHeader(http.StatusOK)
}

func (h *PasskeyHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	tenantNS := mw.GetTenantCode(r.Context())
	if email == "" {
		// Conditional mediation: browser requests discoverable credentials without email.
		// Return 200 with empty JSON body — no error, no options, JS continues gracefully.
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "no-email"})
		return
	}
	options, _, err := h.passkey.BeginLogin(r.Context(), email, tenantNS)
	if err != nil {
		identity.Logf("ERROR BeginLogin: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no passkey"})
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
	tenantNS := user.TenantNS
	if tenantNS == "" {
		tenantNS = mw.GetTenantCode(r.Context())
	}
	identity.Logf("Login successful for %s in NS=%s", httputil.MaskEmail(user.Email), tenantNS)
	pair, err := h.tokens.IssueSession(r.Context(), user.Email, tenantNS, "", "worker")
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "token issue"})
		return
	}
	setAuthCookies(w, pair)
	if h.audit != nil {
		_ = h.audit.LogSecurityEvent(r.Context(), audit.SecurityEvent{
			ActorID: user.ActorID, ActorEmailMasked: httputil.MaskEmail(user.Email),
			Action: "passkey.login", Status: "success",
			ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
		})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/dashboard"})
}

// PasskeyPresenceFunc adapts a function to PasskeyPresence.
type PasskeyPresenceFunc func(ctx context.Context, tenantNS, email string) bool

// HasPasskey implements PasskeyPresence.
func (f PasskeyPresenceFunc) HasPasskey(ctx context.Context, tenantNS, email string) bool {
	return f(ctx, tenantNS, email)
}
