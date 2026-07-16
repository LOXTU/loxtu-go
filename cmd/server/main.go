// Package main is the LOXTU application entry point.
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

	"github.com/loxtu/loxtu-go/internal/features/auth"
	"github.com/loxtu/loxtu-go/internal/features/dashboard"
	"github.com/loxtu/loxtu-go/internal/features/passkey"
	"github.com/loxtu/loxtu-go/internal/infrastructure/email"
	"github.com/loxtu/loxtu-go/internal/platform/audit"
	"github.com/loxtu/loxtu-go/internal/platform/db"
	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	addr := envOr("LISTEN_ADDR", "0.0.0.0:8880")
	log.Printf("[main] LOXTU starting on %s", addr)
	log.Printf("[main] LOXTU_VERSION=%s", envOr("LOXTU_VERSION", "dev"))

	// ── Step 1: Initialise DB Connection Pool ──
	pool, err := db.PoolFromEnv()
	if err != nil {
		log.Fatalf("[main] DB pool init failed: %v", err)
	}
	db.DB = pool

	// Run control_plane migration
	cpSQL := db.LoadMigrationFile("internal/platform/db/migrations/control_plane/001_tenant.surrealql")
	if cpSQL != "" {
		if err := db.RunMigration("control_plane", cpSQL); err != nil {
			log.Printf("[main] WARNING: control_plane migration failed: %v", err)
		}
	}

	// Seed development data (3 tenants + their NS migrations)
	db.SeedDevelopmentData()

	// Run audit migration
	if err := audit.RunMigration(); err != nil {
		log.Printf("[main] WARNING: audit migration failed: %v", err)
	}

	log.Printf("[main] Database ready")

	// ── Step 2: Email Client ──
	emailCfg := email.DefaultConfig()
	emailClient := email.New(emailCfg)
	auth.EmailClient = emailClient

	// ── Step 3: WebAuthn Passkey ──
	passkey.InitWebAuthn("app.loxtu.com", "https://app.loxtu.com")

	// ── Step 4: Router ──
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(mw.TenantRouter)
	r.Use(mw.DBContext)
	r.Use(mw.RequestID)
	r.Use(mw.SecurityHeaders)

	// Static files (logged separately to avoid noise; use Write/ReadTimeout)
	fileServer := http.FileServer(http.Dir("./web/static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/static/icons/favicon.svg")
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Auth group (CSRF + RateLimit, NO Guard)
	authPublicPaths := []string{
		"/health", "/auth/otp/send", "/auth/otp/verify",
		"/auth/passkey/begin", "/auth/passkey/finish",
		"/auth/passkey/skip", "/auth/passkey/register",
		"/auth/passkey/login/begin", "/auth/passkey/login/finish",
		"/auth/refresh", "/auth/logout", "/auth/consent", "/static/",
	}
	r.Group(func(r chi.Router) {
		r.Use(mw.CSRF(authPublicPaths))
		r.Use(mw.RateLimit(nil))
		auth.Mount(r)
		passkey.Mount(r)
	})

	// Protected group (with Guard)
	r.Group(func(r chi.Router) {
		r.Use(auth.Guard)
		dashboard.Mount(r)
	})

	// ── Step 5: HTTP Server with Graceful Shutdown ──
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown goroutine
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

		if db.DB != nil {
			db.DB.Close()
			log.Printf("[main] DB pool connections closed")
		}

		log.Printf("[main] Server exited cleanly")
	}()

	log.Printf("[main] LOXTU listening on %s", addr)
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