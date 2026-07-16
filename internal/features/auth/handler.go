package auth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/loxtu/loxtu-go/internal/features/shared/httputil"
	"github.com/loxtu/loxtu-go/internal/platform/audit"
	"github.com/loxtu/loxtu-go/internal/platform/db"
	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

func Mount(r chi.Router) {
	r.Get("/", handleLoginPage)
	r.Post("/auth/otp/send", handleSendOTP)
	r.Post("/auth/otp/verify", handleVerifyOTP)
	r.Get("/auth/consent", handleConsentPage)
	r.Post("/auth/consent", handleConsentAccept)
	r.Post("/auth/refresh", handleRefresh)
	r.Post("/auth/logout", handleLogout)
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if httputil.WantsJSON(r) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{
			"type": "login", "message": "Login form endpoint",
		})
		return
	}
	templ.Handler(LoginShell()).ServeHTTP(w, r)
}

// ─── Progressive Profiling ────────────────────────────────────────────────
// Step 1: OTP Send — create minimal user record if not exists.

func handleSendOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" || !strings.Contains(email, "@") {
		templ.Handler(LoginFormPartial()).ServeHTTP(w, r)
		return
	}
	if !globalRL.AllowSend(email) {
		msg := "Too many attempts. Please wait 5 minutes before trying again."
		templ.Handler(OTPErrorPartial(email, msg)).ServeHTTP(w, r)
		return
	}
	if _, err := Send(email); err != nil {
		log.Printf("otp send error: %v", err)
		templ.Handler(LoginFormPartial()).ServeHTTP(w, r)
		return
	}
	globalRL.RecordSend(email)

	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}

	// Step 1: Create or find user by email_hash
	emailHash := db.EmailHash(email)
	actorID := db.LookupUserIDByEmailHash(tenantNS, emailHash)
	if actorID == "" {
		// Create minimal user record — first touch
		results, err := db.QueryCtx(r.Context(), tenantNS, tenantNS,
			"CREATE users SET email_hash = $hash, tenant_id = $tenant, is_active = false RETURN id",
			map[string]any{
				"hash":   emailHash,
				"tenant": tenantNS,
			},
		)
		if err != nil {
			log.Printf("[auth] WARNING: create user failed (race?): %v — retrying lookup", err)
			// Race condition: another request created the same user between our SELECT and CREATE.
			// Retry lookup — the record now exists.
			actorID = db.LookupUserIDByEmailHash(tenantNS, emailHash)
		} else if len(results) > 0 {
			if rows, ok := results[0].Result.([]any); ok && len(rows) > 0 {
				if row, ok := rows[0].(map[string]any); ok {
					if id, ok := row["id"]; ok {
						actorID = db.FormatRecordID(id)
						// ✅ ИСПРАВЛЕНО: добавлен 3-й аргумент tenantNS и исправлен формат строки
						log.Printf("[auth] Created minimal user %s for %s in NS=%s", actorID, mw.MaskEmail(email), tenantNS)
					}
				}
			}
		}
	}
	// actorID must be set — if still empty after all attempts, fail gracefully
	if actorID == "" {
		log.Printf("[auth] CRITICAL: cannot resolve actor_id for %s", mw.MaskEmail(email))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Pre-auth state cookie
	cookieVal := fmt.Sprintf(`{"email":"%s","tenant_ns":"%s"}`, email, tenantNS)
	http.SetCookie(w, &http.Cookie{
		Name: "pre_auth_state", Value: url.QueryEscape(cookieVal),
		Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	// Audit: OTP send event
	audit.LogSecurityEvent(audit.SecurityEvent{
		ActorID:          actorID,
		ActorEmailMasked: mw.MaskEmail(email),
		Action:           "auth.otp.send",
		Status:           "success",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})

	templ.Handler(OTPFormPartial(email)).ServeHTTP(w, r)
}

// ─── Step 2: OTP Verify — use existing actor_id ──────────────────────────

func handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	codes := r.Form["code"]
	code := strings.Join(codes, "")

	if globalRL.IsBlocked(email) {
		msg := "Too many attempts. Please wait 5 minutes before trying again."
		templ.Handler(OTPErrorPartial(email, msg)).ServeHTTP(w, r)
		return
	}

	if !Verify(email, code) {
		globalRL.RecordFail(email)
		audit.LogSecurityEvent(audit.SecurityEvent{
			ActorEmailMasked: mw.MaskEmail(email),
			Action:           "auth.otp.verify",
			Status:           "failure",
			ClientIP:         mw.GetClientIP(r),
			ReqID:            mw.GetRequestID(r.Context()),
		})
		templ.Handler(OTPErrorPartial(email, "Invalid or expired code. Try again.")).ServeHTTP(w, r)
		return
	}

	globalRL.Reset(email)

	// ✅ ИСПРАВЛЕНО: ищем по хэшу, а не по plain email (так как поле email еще пустое)
	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}

	emailHash := db.EmailHash(email)
	actorID := db.LookupUserIDByEmailHash(tenantNS, emailHash)
	if actorID == "" {
		log.Printf("[auth] ERROR: user not found for %s after OTP verify", mw.MaskEmail(email))
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	consentOK := audit.CheckConsent(actorID, mw.MaskEmail(email))

	if consentOK == audit.ConsentGranted {
		tokens, refreshPlain, err := IssueTokens(email, tenantNS, "", "worker")
		if err != nil {
			log.Printf("ERROR IssueTokens: %v", err)
		} else {
			audit.LogSecurityEvent(audit.SecurityEvent{
				ActorID:          actorID,
				ActorEmailMasked: mw.MaskEmail(email),
				Action:           "auth.otp.verify",
				Status:           "success",
				ClientIP:         mw.GetClientIP(r),
				ReqID:            mw.GetRequestID(r.Context()),
			})
			http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: tokens, Path: "/", MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: refreshPlain, Path: "/", MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
			http.SetCookie(w, &http.Cookie{Name: "pre_auth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		}
		return
	}

	// Consent required
	setConsentSession(w, email)
	audit.LogSecurityEvent(audit.SecurityEvent{
		ActorID:          actorID,
		ActorEmailMasked: mw.MaskEmail(email),
		Action:           "auth.otp.verify",
		Status:           "success",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})
	http.Redirect(w, r, "/auth/consent?email="+url.QueryEscape(email), http.StatusSeeOther)
}

// ── Consent Flow ───────────────────────────────────────────────────────────

func setConsentSession(w http.ResponseWriter, email string) {
	http.SetCookie(w, &http.Cookie{
		Name: "loxtu_consent", Value: email, Path: "/",
		MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func handleConsentPage(w http.ResponseWriter, r *http.Request) {
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
	templ.Handler(ConsentPage(email)).ServeHTTP(w, r)
}

func handleConsentAccept(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	gdpr := r.FormValue("gdpr")
	nis2 := r.FormValue("nis2")
	soc2 := r.FormValue("soc2")

	if email == "" || gdpr == "" || nis2 == "" || soc2 == "" {
		templ.Handler(ConsentPage(email)).ServeHTTP(w, r)
		return
	}

	// ✅ ИСПРАВЛЕНО: ищем по хэшу, а не по plain email

	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}

	emailHash := db.EmailHash(email)
	actorID := db.LookupUserIDByEmailHash(tenantNS, emailHash)
	if actorID == "" {
		log.Printf("[auth] ERROR: user not found for %s on consent accept", mw.MaskEmail(email))
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	maskedEmail := mw.MaskEmail(email)

	audit.LogConsentEvent(audit.ConsentEvent{
		ActorID:          actorID,
		ActorEmailMasked: maskedEmail,
		PrivacyPolicy:    "v1",
		TermsOfService:   "v1",
		ConsentTypes:     "gdpr,nis2,soc2",
		ClientIP:         mw.GetClientIP(r),
		ReqID:            mw.GetRequestID(r.Context()),
	})

	http.SetCookie(w, &http.Cookie{Name: "loxtu_consent", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})

	if db.HasPasskeyCredentials(tenantNS, email) {
		tokens, refreshPlain, err := IssueTokens(email, tenantNS, "", "worker")
		if err == nil {
			http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: tokens, Path: "/", MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: refreshPlain, Path: "/", MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	redirectURL := "/auth/passkey/register?email=" + url.QueryEscape(email)
	w.Header().Set("HX-Redirect", redirectURL)
	w.WriteHeader(http.StatusOK)
}

// ── Refresh ───────────────────────────────────────────────────────────────

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("loxtu_refresh")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	
	// ✅ ИСПРАВЛЕНО: получаем tenantNS для ротации
	tenantNS := mw.GetTenantCode(r.Context())
	if tenantNS == "" {
		tenantNS = "public"
	}

	// ✅ ИСПРАВЛЕНО: передаем tenantNS первым аргументом
	accessToken, newRefreshPlain, err := RotateRefreshToken(tenantNS, cookie.Value)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: accessToken, Path: "/", MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: newRefreshPlain, Path: "/", MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// ── Step 4: Logout — resilient ──────────────────────────────────────────

func handleLogout(w http.ResponseWriter, r *http.Request) {
	email := ""
	tenantNS := "public" // Безопасный fallback на случай, если токен битый

	if c, err := r.Cookie("loxtu_access"); err == nil {
		token, _, _ := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(c.Value, &AccessClaims{})
		if token != nil {
			if claims, ok := token.Claims.(*AccessClaims); ok {
				email = claims.Email
				// 🔥 ИСТОЧНИК ИСТИНЫ: берем TenantNS из токена, так как мы сами его туда записали при логине
				if claims.TenantNS != "" {
					tenantNS = claims.TenantNS
				}
			}
		}
	}
	
	log.Printf("[auth] Logout for %s (reqid=%s)", mw.MaskEmail(email), mw.GetRequestID(r.Context()))
	
	if email != "" {
		// 🔥 Используем правильный tenantNS из токена, а не хардкод
		actorID := db.LookupUserIDByEmail(tenantNS, email)
		
		if err := RevokeAllSessions(tenantNS, email); err != nil {
			log.Printf("[auth] WARN: Session revocation skipped (non-fatal): %v", err)
		} else {
			log.Printf("[auth] All sessions revoked for %s in NS=%s", mw.MaskEmail(email), tenantNS)
			audit.LogSecurityEvent(audit.SecurityEvent{
				ActorID:          actorID,
				ActorEmailMasked: mw.MaskEmail(email),
				Action:           "auth.logout",
				Status:           "success",
				ClientIP:         mw.GetClientIP(r),
				ReqID:            mw.GetRequestID(r.Context()),
			})
		}
	}
	
	http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: "", Path: "/", MaxAge: -1})
	
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/")
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}