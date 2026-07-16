// Package passkey handles WebAuthn passkey registration and login.
package passkey

import (
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/loxtu/loxtu-go/internal/features/auth"
	"github.com/loxtu/loxtu-go/internal/features/shared/httputil"
	"github.com/loxtu/loxtu-go/internal/platform/audit"
	"github.com/loxtu/loxtu-go/internal/platform/db"
	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

// Mount registers passkey routes on the Chi router.
func Mount(r chi.Router) {
	// Registration
	r.Post("/auth/passkey/begin", handleBeginRegistration)
	r.Post("/auth/passkey/finish", handleFinishRegistration)
	r.Post("/auth/passkey/skip", handleSkipPasskey)
	r.Get("/auth/passkey/register", handleRegisterPage)

	// Login (conditional UI / autofill)
	r.Get("/auth/passkey/login/begin", handleBeginLogin)
	r.Post("/auth/passkey/login/finish", handleFinishLogin)
}

// ── Registration ──────────────────────────────────────────────────────────

func handleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := r.FormValue("email")
	if email == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	Logf("BEGIN registration for %s", mw.MaskEmail(email))

	user, err := FindOrCreateUser(email, mw.GetTenantCode(r.Context()))
	if err != nil {
		Logf("ERROR FindOrCreateUser: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	var exclusions []protocol.CredentialDescriptor
	for _, c := range user.WebAuthnCredentials() {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}
	options, sessionData, err := WebAuthn.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
			ResidentKey:             protocol.ResidentKeyRequirement("required"),
			UserVerification:        protocol.UserVerificationRequirement("required"),
		}),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		Logf("ERROR BeginRegistration: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin"})
		return
	}

	allowedIDs := make([][]byte, len(sessionData.AllowedCredentialIDs))
	copy(allowedIDs, sessionData.AllowedCredentialIDs)

	if err := StoreSession(sessionData.Challenge, &SessionData{
		Challenge:            sessionData.Challenge,
		UserID:               string(user.WebAuthnID()),
		UserEmail:            email,
		TenantNS:             mw.GetTenantCode(r.Context()),
		AllowedCredentialIDs: allowedIDs,
		Expires:              time.Now().Add(5 * time.Minute).Unix(),
		CredParams:           sessionData.CredParams,
	}); err != nil {
		Logf("ERROR StoreSession: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	Logf("Registration options sent for %s (challenge: %s...)", mw.MaskEmail(email), sessionData.Challenge[:8])
	httputil.WriteJSON(w, http.StatusOK, options)
}

func handleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		Logf("ERROR ParseCredentialCreationResponse: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential"})
		return
	}
	challenge := parsed.Response.CollectedClientData.Challenge

	sd, err := GetSession(challenge)
	if err != nil {
		Logf("ERROR session not found for challenge %s...", challenge[:8])
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "session expired or invalid"})
		return
	}
	Logf("FINISH registration for %s", mw.MaskEmail(sd.UserEmail))

	user, err := GetUser(sd.UserEmail, sd.TenantNS)
	if err != nil {
		Logf("ERROR GetUser: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user not found"})
		return
	}

	ws := webauthn.SessionData{
		Challenge:            sd.Challenge,
		UserID:               []byte(sd.UserID),
		AllowedCredentialIDs: sd.AllowedCredentialIDs,
		Expires:              time.Unix(sd.Expires, 0),
		CredParams:           sd.CredParams,
	}
	credential, err := WebAuthn.CreateCredential(user, ws, parsed)
	if err != nil {
		Logf("ERROR CreateCredential: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "verification failed"})
		return
	}

	if err := SaveCredential(sd.UserEmail, sd.TenantNS, credential); err != nil {
		Logf("ERROR SaveCredential: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	Logf("Registration complete for %s", mw.MaskEmail(sd.UserEmail))

	actorID := db.LookupUserIDByEmail(sd.TenantNS, sd.UserEmail)
	audit.LogSecurityEvent(audit.SecurityEvent{
		ActorID:          actorID,
		ActorEmailMasked: mw.MaskEmail(sd.UserEmail),
		Action:           "auth.passkey.register",
		Status:           "success",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})

	setAuthCookies(w, r, sd.UserEmail, sd.TenantNS)

	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: sd.UserEmail, Path: "/", MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "pre_auth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("HX-Redirect", "/dashboard")
	w.WriteHeader(http.StatusOK)
}

// setAuthCookies issues JWT tokens and sets them as cookies.
func setAuthCookies(w http.ResponseWriter, r *http.Request, email, tenantNS string) {
	if tenantNS == "" {
		tenantNS = "public"
	}
	if tokens, refreshPlain, err := auth.IssueTokens(email, tenantNS, "", "worker"); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name: "loxtu_access", Value: tokens, Path: "/",
			MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name: "loxtu_refresh", Value: refreshPlain, Path: "/",
			MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	} else {
		Logf("ERROR IssueTokens: %v", err)
	}
}

// ── Skip Passkey ──────────────────────────────────────────────────────────

func handleSkipPasskey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := r.FormValue("email")
	Logf("SKIP passkey for %s", mw.MaskEmail(email))

	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_passkey_skipped", Value: "true", Path: "/", MaxAge: 86400})
	w.Header().Set("HX-Redirect", "/dashboard")
	w.WriteHeader(http.StatusOK)
}

// ── Register Page ─────────────────────────────────────────────────────────

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		if err := r.ParseForm(); err == nil {
			email = r.FormValue("email")
		}
	}
	if email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	Logf("Rendering passkey register page for %s", mw.MaskEmail(email))
	templ.Handler(Page(email)).ServeHTTP(w, r)
}

// ── Login (Conditional UI) ────────────────────────────────────────────────

func handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	Logf("BEGIN login (discoverable)")

	options, sessionData, err := WebAuthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		Logf("ERROR BeginDiscoverableMediatedLogin: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin"})
		return
	}

	if err := StoreSession(sessionData.Challenge, &SessionData{
		Challenge: sessionData.Challenge,
		TenantNS:  mw.GetTenantCode(r.Context()),
		Expires:   time.Now().Add(5 * time.Minute).Unix(),
	}); err != nil {
		Logf("ERROR StoreSession (login): %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	Logf("Login options sent (challenge: %s...)", sessionData.Challenge[:8])
	httputil.WriteJSON(w, http.StatusOK, options)
}

// handleFinishLogin completes the WebAuthn login ceremony.
// 🔥 ЭЛЕГАНТНОЕ РЕШЕНИЕ: TenantNS извлекается из найденного пользователя,
// а не парсится из userHandle или угадывается по контексту.
func handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	Logf("FINISH login")
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		Logf("ERROR ParseCredentialRequestResponse: %v", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid assertion"})
		return
	}
	challenge := parsed.Response.CollectedClientData.Challenge

	sd, err := GetSession(challenge)
	if err != nil {
		Logf("ERROR session not found (login): %s...", challenge[:8])
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "session expired or invalid"})
		return
	}
	Logf("FINISH login for challenge %s...", challenge[:8])

	// 1. Находим пользователя. Третий аргумент — fallback, не критичен,
	// потому что настоящая магия произойдет на шаге 2.
	user, err := FindUserByWebAuthnID(parsed.RawID, parsed.Response.UserHandle, "public")
	if err != nil {
		Logf("ERROR FindUserByWebAuthnID: %v", err)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	// 2. 🔥 ЭЛЕГАНТНОСТЬ: Делаем type assertion к нашей конкретной структуре,
	// чтобы получить достоверный TenantNS, который определила база данных.
	// Это работает для любого провайдера: WebAuthn, Apple, Google, Entra ID —
	// главное, чтобы они возвращали объект с полем TenantNS.
	pkUser, ok := user.(*PasskeyUser)
	if !ok {
		Logf("ERROR: unexpected user type %T", user)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Теперь у нас есть 100% достоверный tenantNS из базы данных.
	correctTenantNS := pkUser.TenantNS
	email := pkUser.Email

	if correctTenantNS == "" {
		correctTenantNS = "public"
	}

	ws := webauthn.SessionData{
		Challenge:            sd.Challenge,
		UserID:               user.WebAuthnID(),
		AllowedCredentialIDs: sd.AllowedCredentialIDs,
		Expires:              time.Unix(sd.Expires, 0),
	}

	credential, err := WebAuthn.ValidateLogin(user, ws, parsed)
	if err != nil {
		Logf("ERROR ValidateLogin: %v", err)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "verification failed"})
		return
	}

	// 3. 🔥 Используем correctTenantNS ВЕЗДЕ ниже. Больше никаких гаданий.
	UpdateCredentialSignCount(email, credential.ID, int(credential.Authenticator.SignCount), correctTenantNS)

	Logf("Login successful for %s in NS=%s", mw.MaskEmail(email), correctTenantNS)

	// Audit event
	actorIDLogin := db.LookupUserIDByEmail(correctTenantNS, email)
	audit.LogSecurityEvent(audit.SecurityEvent{
		ActorID:          actorIDLogin,
		ActorEmailMasked: mw.MaskEmail(email),
		Action:           "auth.passkey.login",
		Status:           "success",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})

	// Issue JWT tokens с правильным tenantNS
	setAuthCookies(w, r, email, correctTenantNS)

	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "pre_auth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("HX-Redirect", "/dashboard")
	w.WriteHeader(http.StatusOK)
}