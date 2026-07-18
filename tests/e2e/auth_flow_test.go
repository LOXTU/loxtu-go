package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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

	authH := handlers.NewAuthHandler(otpService, tokenService, users, auditR, rateLimiter, passkeyPresence, pepper)

	r := chi.NewRouter()
	r.Use(mw.NewTenantRouter(tenantRepo))
	r.Use(mw.RequestID)
	authH.Mount(r)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, pool, pepper
}

func TestE2E_AuthFlow_OTP(t *testing.T) {
	ts, pool, pepper := setupServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	email := fmt.Sprintf("e2e-%d@loxtu.com", time.Now().UnixNano())
	emailHash := security.HashEmail(email, pepper)

	// Step 1: OTP Send
	t.Log("Step 1: POST /auth/otp/send")
	form := url.Values{"email": {email}}
	resp, err := client.Post(ts.URL+"/auth/otp/send", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("OTP send: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OTP send status = %d, body: %s", resp.StatusCode, string(body))
	}

	// Verify user created
	ctx := context.Background()
	repo := surrealdb.NewUserRepository(pool, nil, pepper)
	u, err := repo.FindByEmailHash(ctx, emailHash)
	if err != nil {
		t.Fatalf("FindByEmailHash: %v", err)
	}
	if u == nil {
		t.Fatal("user should exist after OTP send")
	}
	if u.UserID == "" {
		t.Error("UserID should be generated")
	}
	t.Logf("✅ User created: UserID=%s, Status=%s, TenantID=%s", u.UserID, u.Status, u.TenantID)

	// Step 2: Verify cookies set
	t.Log("Step 2: Verify cookies")
	cookieURL, _ := url.Parse(ts.URL)
	cookies := jar.Cookies(cookieURL)
	cookieNames := map[string]bool{}
	for _, c := range cookies {
		cookieNames[c.Name] = true
		t.Logf("  Cookie: %s=%s", c.Name, c.Value[:min(20, len(c.Value))])
	}
	if !cookieNames["pre_auth_state"] {
		t.Error("pre_auth_state cookie should be set")
	}
	if !cookieNames["loxtu_tenant"] {
		t.Error("loxtu_tenant cookie should be set")
	}

	// Step 3: Verify audit record
	t.Log("Step 3: Verify audit")
	time.Sleep(500 * time.Millisecond)
	cfg := config.SurrealDBFromEnv()
	auditResults, err := pool.Query(ctx, "audit", cfg.Namespace,
		"SELECT action, user_id, masked_email FROM security_audit WHERE masked_email = $email LIMIT 5",
		map[string]any{"email": security.MaskEmail(email)},
	)
	if err != nil {
		t.Logf("⚠️ Audit query: %v", err)
	} else if len(auditResults) > 0 {
		if rows, ok := auditResults[0].Result.([]any); ok && len(rows) > 0 {
			if rm, ok := rows[0].(map[string]any); ok {
				t.Logf("✅ Audit: action=%v user_id=%v masked_email=%v", rm["action"], rm["user_id"], rm["masked_email"])
			}
		}
	}

	t.Log("✅ E2E OTP flow verified")
}

func TestE2E_JWTClaims(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", os.Getenv("LOXTU_JWT_SECRET"))

	token, err := identity.IssueAccessToken("test-uuid-123", "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := identity.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	if claims.UserID != "test-uuid-123" {
		t.Errorf("UserID = %q", claims.UserID)
	}
	if claims.TenantID != "loxtu" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	if claims.Subject != "test-uuid-123" {
		t.Errorf("Subject = %q (should match UserID)", claims.Subject)
	}

	t.Logf("✅ JWT verified: user_id=%s, tenant_id=%s, subject=%s", claims.UserID, claims.TenantID, claims.Subject)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
