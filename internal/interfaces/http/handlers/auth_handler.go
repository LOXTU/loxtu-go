package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/loxtu/loxtu-go/internal/core/audit"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
	authtmpl "github.com/loxtu/loxtu-go/internal/interfaces/templates/auth"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
)

// ConsentChecker is optional — adapters may implement legacy consent storage.
type ConsentChecker interface {
	// Granted is true when a non-expired consent exists.
	Granted(ctx context.Context, actorID, emailMasked string) bool
	// LogConsent records a consent accept event.
	LogConsent(ctx context.Context, event audit.ConsentEvent) error
}

// PasskeyPresence reports whether the user already enrolled a passkey.
type PasskeyPresence interface {
	HasPasskey(ctx context.Context, tenantNS, email string) bool
}

// AuthHandler is the HTTP surface for OTP / consent / refresh / logout.
type AuthHandler struct {
	otp      *identity.OTPService
	tokens   *identity.TokenService
	users    identity.UserStore
	audit    audit.Store
	rl       identity.RateLimiter
	consent  ConsentChecker  // optional
	passkeys PasskeyPresence // optional
}

// NewAuthHandler constructs an AuthHandler with required dependencies.
// rl is required for OTP send/verify throttling (policy from core/identity).
func NewAuthHandler(
	otp *identity.OTPService,
	tokens *identity.TokenService,
	users identity.UserStore,
	auditStore audit.Store,
	rl identity.RateLimiter,
	consent ConsentChecker,
	passkeys PasskeyPresence,
) *AuthHandler {
	return &AuthHandler{
		otp:      otp,
		tokens:   tokens,
		users:    users,
		audit:    auditStore,
		rl:       rl,
		consent:  consent,
		passkeys: passkeys,
	}
}

// Mount registers auth public routes.
func (h *AuthHandler) Mount(r chi.Router) {
	r.Get("/", h.LoginPage)
	r.Post("/auth/otp/send", h.SendOTP)
	r.Post("/auth/otp/verify", h.VerifyOTP)
	r.Get("/auth/consent", h.ConsentPage)
	r.Post("/auth/consent", h.ConsentAccept)
	r.Post("/auth/refresh", h.Refresh)
	r.Post("/auth/logout", h.Logout)
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"type": "login", "message": "Login form endpoint"})
		return
	}
	templ.Handler(authtmpl.LoginShell()).ServeHTTP(w, r)
}

func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" || !strings.Contains(email, "@") {
		templ.Handler(authtmpl.LoginFormPartial()).ServeHTTP(w, r)
		return
	}
	if h.rl != nil {
		allowed, err := h.rl.Allow(r.Context(), identity.RateKeyOTPSend(email), identity.PolicyOTP)
		if err != nil {
			log.Printf("[auth] rate limit error: %v", err)
		}
		if !allowed {
			msg := "Too many attempts. Please wait before trying again."
			templ.Handler(authtmpl.OTPErrorPartial(email, msg)).ServeHTTP(w, r)
			return
		}
	}
	if _, err := h.otp.Send(r.Context(), email); err != nil {
		log.Printf("otp send error: %v", err)
		templ.Handler(authtmpl.LoginFormPartial()).ServeHTTP(w, r)
		return
	}

	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}

	emailHash := identity.EmailHash(email)
	u, err := h.users.FindByEmailHash(r.Context(), tenantNS, emailHash)
	actorID := ""
	if err == nil && u != nil {
		actorID = u.ActorID
	}
	if actorID == "" {
		actorID, err = h.users.CreateMinimalUser(r.Context(), tenantNS, emailHash)
		if err != nil {
			log.Printf("[auth] CRITICAL: cannot resolve actor_id for %s: %v", httputil.MaskEmail(email), err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	cookieVal := fmt.Sprintf(`{"email":"%s","tenant_ns":"%s"}`, email, tenantNS)
	http.SetCookie(w, &http.Cookie{
		Name: "pre_auth_state", Value: url.QueryEscape(cookieVal),
		Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "loxtu_tenant", Value: tenantNS,
		Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	h.logSecurity(r, audit.SecurityEvent{
		ActorID:          actorID,
		ActorEmailMasked: httputil.MaskEmail(email),
		Action:           "auth.otp.send",
		Status:           "success",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})

	templ.Handler(authtmpl.OTPFormPartial(email)).ServeHTTP(w, r)
}

func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	codes := r.Form["code"]
	code := strings.Join(codes, "")

	if h.rl != nil {
		allowed, err := h.rl.Allow(r.Context(), identity.RateKeyOTPFail(email), identity.PolicyOTP)
		if err != nil {
			log.Printf("[auth] rate limit error: %v", err)
		}
		if !allowed {
			msg := "Too many attempts. Please wait before trying again."
			templ.Handler(authtmpl.OTPErrorPartial(email, msg)).ServeHTTP(w, r)
			return
		}
	}
	if !h.otp.Verify(email, code) {
		h.logSecurity(r, audit.SecurityEvent{
			ActorEmailMasked: httputil.MaskEmail(email),
			Action:           "auth.otp.verify",
			Status:           "failure",
			ClientIP:         mw.GetClientIP(r),
			ReqID:            mw.GetRequestID(r.Context()),
		})
		templ.Handler(authtmpl.OTPErrorPartial(email, "Invalid or expired code. Try again.")).ServeHTTP(w, r)
		return
	}
	if h.rl != nil {
		_ = h.rl.Reset(r.Context(), identity.RateKeyOTPSend(email))
		_ = h.rl.Reset(r.Context(), identity.RateKeyOTPFail(email))
	}

	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}
	u, err := h.users.FindByEmailHash(r.Context(), tenantNS, identity.EmailHash(email))
	if err != nil || u == nil || u.ActorID == "" {
		log.Printf("[auth] ERROR: user not found for %s after OTP verify", httputil.MaskEmail(email))
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}
	actorID := u.ActorID
	masked := httputil.MaskEmail(email)

	granted := h.consent != nil && h.consent.Granted(r.Context(), actorID, masked)
	if granted {
		if err := h.issueCookies(w, r, email, tenantNS, actorID, "auth.otp.verify"); err != nil {
			log.Printf("ERROR IssueTokens: %v", err)
		} else {
			w.Header().Set("HX-Redirect", "/dashboard")
			w.WriteHeader(http.StatusOK)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "loxtu_consent", Value: email, Path: "/",
		MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	h.logSecurity(r, audit.SecurityEvent{
		ActorID: actorID, ActorEmailMasked: masked,
		Action: "auth.otp.verify", Status: "success",
		ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
	})
	// Swap consent partial into #auth-container (SPA-like).
	templ.Handler(authtmpl.ConsentPartial(email)).ServeHTTP(w, r)
}

func (h *AuthHandler) ConsentPage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		if c, err := r.Cookie("loxtu_consent"); err == nil && c.Value != "" {
			email = c.Value
		}
	}
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// HTMX partial swap into #auth-container (SPA-like).
	templ.Handler(authtmpl.ConsentPartial(email)).ServeHTTP(w, r)
}

func (h *AuthHandler) ConsentAccept(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	gdpr := r.FormValue("gdpr")
	nis2 := r.FormValue("nis2")
	soc2 := r.FormValue("soc2")
	if email == "" || gdpr == "" || nis2 == "" || soc2 == "" {
		templ.Handler(authtmpl.ConsentPage(email)).ServeHTTP(w, r)
		return
	}
	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}
	u, err := h.users.FindByEmailHash(r.Context(), tenantNS, identity.EmailHash(email))
	if err != nil || u == nil {
		log.Printf("[auth] ERROR: user not found for %s on consent accept", httputil.MaskEmail(email))
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}
	masked := httputil.MaskEmail(email)
	ce := audit.ConsentEvent{
		ActorID: u.ActorID, ActorEmailMasked: masked,
		PrivacyPolicy: "v1", TermsOfService: "v1", ConsentTypes: "gdpr,nis2,soc2",
		ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
	}
	if h.consent != nil {
		_ = h.consent.LogConsent(r.Context(), ce)
	}

	http.SetCookie(w, &http.Cookie{Name: "loxtu_consent", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{
		Name: "loxtu_tenant", Value: tenantNS,
		Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	if h.passkeys != nil && h.passkeys.HasPasskey(r.Context(), tenantNS, email) {
		_ = h.issueCookies(w, r, email, tenantNS, u.ActorID, "auth.consent.accept")
		// Already has passkey → swap to redirect signal (HX-Redirect handles SPA navigation to dashboard).
		w.Header().Set("HX-Redirect", "/dashboard")
		w.WriteHeader(http.StatusOK)
		return
	}
	// No passkey → swap passkey register partial into #auth-container.
	templ.Handler(authtmpl.RegisterPartial(email)).ServeHTTP(w, r)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("loxtu_refresh")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}
	pair, err := h.tokens.Rotate(r.Context(), tenantNS, cookie.Value)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	setAuthCookies(w, pair)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	email := ""
	tenantNS := "public"
	if c, err := r.Cookie("loxtu_access"); err == nil {
		token, _, _ := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(c.Value, &identity.AccessClaims{})
		if token != nil {
			if claims, ok := token.Claims.(*identity.AccessClaims); ok {
				email = claims.Email
				if claims.TenantNS != "" {
					tenantNS = claims.TenantNS
				}
			}
		}
	}
	log.Printf("[auth] Logout for %s (reqid=%s)", httputil.MaskEmail(email), mw.GetRequestID(r.Context()))
	if email != "" {
		if err := h.tokens.RevokeAllForEmail(r.Context(), tenantNS, email); err != nil {
			log.Printf("[auth] WARN: Session revocation skipped (non-fatal): %v", err)
		} else {
			u, _ := h.users.FindByEmailHash(r.Context(), tenantNS, identity.EmailHash(email))
			actorID := ""
			if u != nil {
				actorID = u.ActorID
			}
			h.logSecurity(r, audit.SecurityEvent{
				ActorID: actorID, ActorEmailMasked: httputil.MaskEmail(email),
				Action: "auth.logout", Status: "success",
				ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
			})
		}
	}
	clearAuthCookies(w)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/")
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (h *AuthHandler) issueCookies(w http.ResponseWriter, r *http.Request, email, tenantNS, actorID, action string) error {
	pair, err := h.tokens.IssueSession(r.Context(), email, tenantNS, "", "worker")
	if err != nil {
		return err
	}
	h.logSecurity(r, audit.SecurityEvent{
		ActorID: actorID, ActorEmailMasked: httputil.MaskEmail(email),
		Action: action, Status: "success",
		ClientIP: mw.GetClientIP(r), ReqID: mw.GetRequestID(r.Context()),
	})
	setAuthCookies(w, pair)
	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "pre_auth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{
		Name: "loxtu_tenant", Value: tenantNS,
		Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (h *AuthHandler) logSecurity(r *http.Request, ev audit.SecurityEvent) {
	if h.audit == nil {
		return
	}
	_ = h.audit.LogSecurityEvent(r.Context(), ev)
}

func setAuthCookies(w http.ResponseWriter, pair identity.TokenPair) {
	http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: pair.AccessToken, Path: "/", MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: pair.RefreshPlain, Path: "/", MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_tenant", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "pre_auth_state", Value: "", Path: "/", MaxAge: -1})
}
