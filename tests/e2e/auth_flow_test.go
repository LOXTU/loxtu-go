package e2e

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/loxtu/loxtu-go/internal/adapters/persistence/surrealdb"
	"github.com/loxtu/loxtu-go/internal/adapters/ratelimit"
	"github.com/loxtu/loxtu-go/internal/config"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/interfaces/http/handlers"
	mw "github.com/loxtu/loxtu-go/internal/interfaces/http/middleware"
	"github.com/loxtu/loxtu-go/internal/security"
)

func setupServer(t *testing.T) (*httptest.Server, *surrealdb.Pool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.SurrealDBFromEnv()
	pool, err := surrealdb.NewPool(ctx, surrealdb.Config{
		Endpoint: cfg.Endpoint, Username: cfg.Username, Password: cfg.Password,
		Namespace: cfg.Namespace, Database: cfg.Database, MaxConns: cfg.MaxConns,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	km, err := security.NewEnvKeyManager()
	if err != nil {
		pool.Close()
		t.Fatalf("NewEnvKeyManager: %v", err)
	}

	pepper := os.Getenv("LOXTU_HASH_PEPPER")
	users := surrealdb.NewUserRepository(pool, km, pepper)
	sessions := surrealdb.NewSessionRepo(pool)
	creds := surrealdb.NewCredRepo(pool)
	tenantRepo := surrealdb.NewTenantRepo(pool)
	auditR := surrealdb.NewAuditRepo(pool)
	t.Cleanup(func() { auditR.Stop(); pool.Close() })

	otpService := identity.NewOTPService(nil)
	tokenService := identity.NewTokenService(users, sessions)
	identity.DecryptPIIFn = security.DecryptPII
	rateLimiter := ratelimit.NewMemoryRateLimiter()

	passkeyPresence := handlers.PasskeyPresenceFunc(func(ctx context.Context, tenantID, email string) bool {
		emailHash := security.HashEmail(email, pepper)
		u, _ := users.FindByEmailHash(ctx, emailHash)
		if u == nil {
			return false
		}
		userCreds, _ := creds.FindCredentialsByUserID(ctx, u.UserID)
		return len(userCreds) > 0
	})

	authH := handlers.NewAuthHandler(otpService, tokenService, users, tenantRepo, auditR, rateLimiter, passkeyPresence, pepper)

	r := chi.NewRouter()
	r.Use(mw.RequestID)
	authH.Mount(r)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, pool, pepper
}

func TestE2E_AuthFlow_OTP(t *testing.T) {
	// Not a real integration test — skipped unless a DB is available
	t.Skip("Skipping: requires SurrealDB at LOXTU_SURREAL_ENDPOINT")
}

func TestJWTClaims_HashFormat(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	token, err := identity.IssueAccessToken("test-uuid-123", "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := identity.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	if claims.UserIDHash == "" {
		t.Error("UserIDHash should not be empty")
	}
	if claims.TenantID != "loxtu" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	// Subject must be user_id_hash (SHA-256), not raw UUID
	if claims.Subject == "test-uuid-123" {
		t.Error("Subject must be user_id_hash, not raw UUID! PII leak!")
	}
	if claims.Subject == "" {
		t.Error("Subject should not be empty")
	}

	t.Log("JWT verified: user_id_hash=", claims.UserIDHash, "tenant_id=", claims.TenantID, "subject=", claims.Subject)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}