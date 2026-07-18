// Package main is the LOXTU Composition Root: config → adapters → core → HTTP.
// No package-level service locators (db.DB, EmailClient). Only constructor DI.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/loxtu/loxtu-go/internal/adapters/messaging/smtp"
	"github.com/loxtu/loxtu-go/internal/adapters/oauth"
	"github.com/loxtu/loxtu-go/internal/adapters/persistence/surrealdb"
	"github.com/loxtu/loxtu-go/internal/adapters/ratelimit"
	"github.com/loxtu/loxtu-go/internal/config"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/interfaces/http/handlers"
	imw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
	"github.com/loxtu/loxtu-go/internal/security"
	"github.com/loxtu/loxtu-go/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	addr := envOr("LISTEN_ADDR", "0.0.0.0:8880")
	log.Printf("[main] LOXTU starting on %s", addr)
	log.Printf("[main] LOXTU_VERSION=%s", envOr("LOXTU_VERSION", "dev"))

	// ── Config (ENV only here / config package) ───────────────────────────
	dbCfg := config.SurrealDBFromEnv()
	smtpCfg := config.SMTPFromEnv()
	rpID := envOr("WEBAUTHN_RPID", "app.loxtu.com")
	rpOrigin := envOr("WEBAUTHN_ORIGIN", "https://app.loxtu.com")

	if os.Getenv("LOXTU_JWT_SECRET") == "" {
		log.Fatal("[main] LOXTU_JWT_SECRET is not set")
	}
	secCfg, err := config.SecurityFromEnv()
	if err != nil {
		log.Fatalf("[main] Security config: %v", err)
	}

	// Wire DecryptPIIFn for core PII decryption
	identity.DecryptPIIFn = security.DecryptPII

	// ── Adapters ──────────────────────────────────────────────────────────
	ctx, cancelInit := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := surrealdb.NewPool(ctx, surrealdb.Config{
		Endpoint:  dbCfg.Endpoint,
		Username:  dbCfg.Username,
		Password:  dbCfg.Password,
		Namespace: dbCfg.Namespace,
		Database:  dbCfg.Database,
		MaxConns:  dbCfg.MaxConns,
	})
	cancelInit()
	if err != nil {
		log.Fatalf("[main] DB pool init failed: %v", err)
	}
	defer pool.Close()

	km, err := security.NewEnvKeyManager()
	if err != nil {
		log.Fatalf("[main] KeyManager init failed: %v", err)
	}

	users := surrealdb.NewUserRepository(pool, km, secCfg.HashPepper)
	sessions := surrealdb.NewSessionRepo(pool)
	creds := surrealdb.NewCredRepo(pool)
	tenantRepo := surrealdb.NewTenantRepo(pool)
	auditR := surrealdb.NewAuditRepo(pool)
	defer auditR.Stop()

	mail := smtp.New(smtp.Config{
		Host:          smtpCfg.Host,
		Port:          smtpCfg.Port,
		User:          smtpCfg.User,
		Password:      smtpCfg.Password,
		FromAddr:      smtpCfg.FromAddr,
		FromName:      smtpCfg.FromName,
		Enabled:       smtpCfg.Enabled,
		Timeout:       smtpCfg.Timeout,
		TLSServerName: smtpCfg.TLSServerName,
	})

	// ── Core services ─────────────────────────────────────────────────────
	otpService := identity.NewOTPService(mail)
	tokenService := identity.NewTokenService(users, sessions)

	wa, err := identity.NewWebAuthn(rpID, rpOrigin)
	if err != nil {
		log.Fatalf("[main] WebAuthn init failed: %v", err)
	}
	passkeyService := identity.NewPasskeyService(users, creds, wa, secCfg.HashPepper)

	rateLimiter := ratelimit.NewMemoryRateLimiter()
	passkeyPresence := handlers.PasskeyPresenceFunc(func(ctx context.Context, tenantID, email string) bool {
		// Resolve user by email hash, then check if they have credentials
		emailHash := security.HashEmail(email, secCfg.HashPepper)
		u, err := users.FindByEmailHash(ctx, emailHash)
		if err != nil || u == nil {
			return false
		}
		userCreds, _ := creds.FindCredentialsByUserID(ctx, u.UserID)
		return len(userCreds) > 0
	})

	// ── HTTP handlers (constructor DI only) ───────────────────────────────
	authH := handlers.NewAuthHandler(
		otpService,
		tokenService,
		users,
		tenantRepo,
		auditR,
		rateLimiter,
		passkeyPresence,
		secCfg.HashPepper,
	)
	pkH := handlers.NewPasskeyHandler(passkeyService, tokenService, auditR)
	dashH := handlers.NewDashboardHandlerWithTenant(tenantRepo)

	// ── OAuth2 ────────────────────────────────────────────────────────────
	oauthRepo := surrealdb.NewOAuthRepo(pool)
	oauthSvc := identity.NewOAuthService(oauthRepo, users, secCfg.HashPepper)
	// Register providers (only if client IDs are configured)
	if gc := envOr("GOOGLE_CLIENT_ID", ""); gc != "" {
		oauthSvc.RegisterProvider(oauth.NewGoogleProvider(oauth.ProviderConfig{
			ClientID:     gc,
			ClientSecret: envOr("GOOGLE_CLIENT_SECRET", ""),
			RedirectURI:  envOr("GOOGLE_REDIRECT_URI", "https://app.loxtu.com/auth/oauth/google/callback"),
		}))
	}
	if ec := envOr("ENTRA_CLIENT_ID", ""); ec != "" {
		oauthSvc.RegisterProvider(oauth.NewEntraProvider(oauth.ProviderConfig{
			ClientID:     ec,
			ClientSecret: envOr("ENTRA_CLIENT_SECRET", ""),
			RedirectURI:  envOr("ENTRA_REDIRECT_URI", "https://app.loxtu.com/auth/oauth/entra/callback"),
		}))
	}
	if ac := envOr("APPLE_CLIENT_ID", ""); ac != "" {
		oauthSvc.RegisterProvider(oauth.NewAppleProvider(oauth.ProviderConfig{
			ClientID:     ac,
			ClientSecret: envOr("APPLE_CLIENT_SECRET", ""),
			RedirectURI:  envOr("APPLE_REDIRECT_URI", "https://app.loxtu.com/auth/oauth/apple/callback"),
		}))
	}
	oauthH := handlers.NewOAuthHandler(oauthSvc, tokenService)

	// ── Router ────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(imw.NewTenantRouter(tenantRepo))
	r.Use(imw.RequestID)
	r.Use(imw.SecurityHeaders)

	// Static (embedded)
	r.Handle("/static/*", http.FileServer(http.FS(web.StaticFiles)))
	r.Get("/favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := web.StaticFiles.ReadFile("static/icons/favicon.svg")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(data)
	}))
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Auth + passkey (CSRF + rate limit; Guard not applied)
	authPublicPaths := []string{
		"/health", "/auth/otp/send", "/auth/otp/verify",
		"/auth/passkey/begin", "/auth/passkey/finish",
		"/auth/passkey/skip", "/auth/passkey/register",
		"/auth/passkey/login/begin", "/auth/passkey/login/finish",
		"/auth/refresh", "/auth/logout", "/auth/consent", "/static/",
	}
	r.Group(func(r chi.Router) {
		r.Use(imw.CSRF(authPublicPaths))
		r.Use(imw.RateLimit(nil))
		authH.Mount(r)
		pkH.Mount(r)
		oauthH.Mount(r)
	})

	// Protected dashboard
	r.Group(func(r chi.Router) {
		r.Use(handlers.Guard)
		dashH.Mount(r)
	})

	// ── HTTP server + graceful shutdown ──────────────────────────────────
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Printf("[main] Received signal %v — shutting down gracefully...", sig)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[main] HTTP server shutdown error: %v", err)
		}
		log.Printf("[main] Server exiting cleanly")
	}()

	log.Printf("[main] LOXTU listening on %s (composition root: adapters→core→handlers)", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[main] server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
