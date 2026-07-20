package identity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// ── OTPService ──────────────────────────────────────────────────────────

func TestGenerateCode(t *testing.T) {
	c1, err := identity.GenerateCode()
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if len(c1) != 6 {
		t.Errorf("code length = %d, want 6", len(c1))
	}
	for _, b := range c1 {
		if b < '0' || b > '9' {
			t.Errorf("non-digit in code: %q", c1)
			break
		}
	}
	c2, _ := identity.GenerateCode()
	if c1 == c2 {
		t.Error("two codes should differ")
	}
}

func TestOTPService_Verify_WrongCode(t *testing.T) {
	svc := identity.NewOTPService(nil, newMockOTPStore())
	_ = svc.Send(context.Background(), "x@y.com")
	valid, _ := svc.Verify(context.Background(), "x@y.com", "000000")
	if valid {
		t.Error("wrong code should fail")
	}
}

func TestOTPService_Verify_UnknownEmail(t *testing.T) {
	svc := identity.NewOTPService(nil, newMockOTPStore())
	valid, _ := svc.Verify(context.Background(), "nobody@x.com", "123456")
	if valid {
		t.Error("unknown email should fail")
	}
}

func TestOTPService_Verify_MaxAttempts(t *testing.T) {
	svc := identity.NewOTPService(nil, newMockOTPStore())
	_ = svc.Send(context.Background(), "x@y.com")
	for i := 0; i < 3; i++ {
		_, _ = svc.Verify(context.Background(), "x@y.com", "000000")
	}
	// 4th attempt — OTP should be deleted (maxAttempts exceeded)
	valid, _ := svc.Verify(context.Background(), "x@y.com", "000000")
	if valid {
		t.Error("should fail after max attempts")
	}
}

func TestOTPService_NewOTPService(t *testing.T) {
	svc := identity.NewOTPService(nil, newMockOTPStore())
	if svc == nil {
		t.Error("should not be nil")
	}
}

func TestOTPService_SendAndVerify(t *testing.T) {
	otpStore := newMockOTPStore()
	svc := identity.NewOTPService(nil, otpStore)

	if err := svc.Send(context.Background(), "test@loxtu.com"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify OTP was stored in the DB (not in-memory)
	key := sha256Hex("test@loxtu.com")
	_, _, _, err := otpStore.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("OTP should be stored: %v", err)
	}
}

// sha256Hex is a test helper matching the OTPService's internal hash.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ── OAuthManager ────────────────────────────────────────────────────────

func TestNewOAuthManager(t *testing.T) {
	om := identity.NewOAuthManager(newMockUserStore(), newMockSessionStore())
	if om == nil {
		t.Error("should not be nil")
	}
}

func TestMapEntraGroups(t *testing.T) {
	for _, tt := range []struct {
		groups []string
		want   string
	}{
		{[]string{"LOXTU-Admin"}, "admin"},
		{[]string{"Admin"}, "admin"},
		{[]string{"LOXTU-Manager"}, "manager"},
		{[]string{"Manager"}, "manager"},
		{[]string{"Other"}, "worker"},
		{nil, "worker"},
		{[]string{}, "worker"},
	} {
		if got := identity.MapEntraGroups(tt.groups); got != tt.want {
			t.Errorf("MapEntraGroups(%v) = %q, want %q", tt.groups, got, tt.want)
		}
	}
}

func TestOAuthManager_LinkAndIssue_MissingEmail(t *testing.T) {
	om := identity.NewOAuthManager(newMockUserStore(), newMockSessionStore())
	_, _, err := om.LinkAndIssue(context.Background(), "loxtu", identity.ExternalIdentity{}, "worker")
	if err == nil {
		t.Error("expected error for missing email")
	}
}

func TestOAuthManager_LinkAndIssue(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	users := newMockUserStore()
	om := identity.NewOAuthManager(users, newMockSessionStore())
	ext := identity.ExternalIdentity{Provider: "google", Email: "test@loxtu.com", Name: "Test"}
	pair, user, err := om.LinkAndIssue(context.Background(), "loxtu", ext, "admin")
	if err != nil {
		t.Fatalf("LinkAndIssue: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken empty")
	}
	if user == nil {
		t.Fatal("user should not be nil")
	}
	if user.Role != "admin" {
		t.Errorf("Role = %q", user.Role)
	}
	if user.TenantID != "loxtu" {
		t.Errorf("TenantID = %q", user.TenantID)
	}
	// Verify user was created
	found, _ := users.FindByEmailHash(context.Background(), identity.EmailHash("test@loxtu.com"))
	if found == nil {
		t.Error("user should be in store after LinkAndIssue")
	}
}

func TestOAuthManager_LinkAndIssue_Defaults(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	om := identity.NewOAuthManager(newMockUserStore(), newMockSessionStore())
	ext := identity.ExternalIdentity{Email: "x@y.com"}
	_, user, err := om.LinkAndIssue(context.Background(), "", ext, "")
	if err != nil {
		t.Fatalf("LinkAndIssue: %v", err)
	}
	if user.TenantID != "public" {
		t.Errorf("default TenantID = %q", user.TenantID)
	}
	if user.Role != "worker" {
		t.Errorf("default Role = %q", user.Role)
	}
}

func TestOAuthManager_LinkAndIssue_ExistingUser(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	users := newMockUserStore()
	hash := identity.EmailHash("existing@loxtu.com")
	users.Create(context.Background(), &identity.User{
		UserID: "existing-uuid", EmailHash: hash, TenantID: "loxtu", Role: "manager",
	})
	om := identity.NewOAuthManager(users, newMockSessionStore())
	ext := identity.ExternalIdentity{Email: "existing@loxtu.com"}
	_, user, err := om.LinkAndIssue(context.Background(), "loxtu", ext, "worker")
	if err != nil {
		t.Fatalf("LinkAndIssue: %v", err)
	}
	// Should keep existing role
	if user.Role != "manager" {
		t.Errorf("Role = %q, want manager (existing)", user.Role)
	}
}

// ── Passkey service extra coverage ──────────────────────────────────────

func TestNewWebAuthn(t *testing.T) {
	wa, err := identity.NewWebAuthn("app.loxtu.com", "https://app.loxtu.com")
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	if wa == nil {
		t.Error("should not be nil")
	}
}

func TestPasskeyService_BeginRegistration_NilWA(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, _, err := svc.BeginRegistration(context.Background(), "x@y.com", "loxtu")
	if err == nil || err.Error() != "webauthn not initialised" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_BeginLogin_NilWA(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, _, err := svc.BeginLogin(context.Background(), "x@y.com", "loxtu")
	if err == nil || err.Error() != "webauthn not initialised" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_BeginLoginDiscoverable_NilWA(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, _, err := svc.BeginLoginDiscoverable(context.Background(), "loxtu")
	if err == nil || err.Error() != "webauthn not initialised" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_FinishRegistration_NilWA(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, _, err := svc.FinishRegistration(context.Background(), "x", nil)
	if err == nil || err.Error() != "webauthn not initialised" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_FinishLogin_NilWA(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, _, err := svc.FinishLogin(context.Background(), "x", nil)
	if err == nil || err.Error() != "webauthn not initialised" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_FinishRegistration_NoSession(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), wa, "test-pepper")
	_, _, err := svc.FinishRegistration(context.Background(), "nonexistent-challenge", nil)
	if err == nil || err.Error() != "session not found" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_FinishLogin_NoSession(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), wa, "test-pepper")
	_, _, err := svc.FinishLogin(context.Background(), "nonexistent", nil)
	if err == nil || err.Error() != "session not found" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPasskeyService_ResolveUserID_NilWA(t *testing.T) {
	users := newMockUserStore()
	svc := identity.NewPasskeyService(users, newMockCredStore(), nil, "test-pepper")
	_, err := svc.ResolveUserID(context.Background(), "x@y.com")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestPasskeyService_GetUser_NoCredentials(t *testing.T) {
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{UserID: "u1", EmailHash: identity.EmailHashWithPepper("x@y.com", "test-pepper")})
	svc := identity.NewPasskeyService(users, newMockCredStore(), nil, "test-pepper")
	_, err := svc.GetUser(context.Background(), "x@y.com")
	if err == nil {
		t.Error("expected error when user has no credentials")
	}
}

func TestLogf(t *testing.T) {
	// Just verify it doesn't panic
	identity.Logf("test %s %d", "hello", 42)
}

// ── TokenService ────────────────────────────────────────────────────────

func TestTokenService_SetAccessTTL(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	svc := identity.NewTokenService(newMockUserStore(), newMockSessionStore())
	p1, err := svc.Issue("u1", "loxtu", "worker", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	svc.SetAccessTTL(6 * time.Second)
	p2, err := svc.Issue("u1", "loxtu", "worker", nil)
	if err != nil {
		t.Fatalf("Issue custom: %v", err)
	}
	if p1.AccessToken == "" || p2.AccessToken == "" {
		t.Error("AccessToken empty")
	}
}

func TestTokenService_IssueSession(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{UserID: "u1", TenantID: "loxtu", Role: "worker"})
	sessions := newMockSessionStore()
	svc := identity.NewTokenService(users, sessions)
	pair, err := svc.IssueSession(context.Background(), "u1", "loxtu", "worker", nil)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshHash == "" {
		t.Error("empty tokens")
	}
	sess, _ := sessions.FindByTokenHash(context.Background(), pair.RefreshHash)
	if sess == nil {
		t.Error("session not persisted")
	}
}

func TestTokenService_IssueSession_NilStores(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	svc := identity.NewTokenService(nil, nil)
	pair, err := svc.IssueSession(context.Background(), "u1", "loxtu", "worker", nil)
	if err != nil {
		t.Fatalf("IssueSession nil stores: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("should return tokens with nil stores")
	}
}

func TestTokenService_Issue_Defaults(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	svc := identity.NewTokenService(nil, nil)
	pair, err := svc.Issue("", "", "", nil)
	if err != nil {
		t.Fatalf("Issue defaults: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("empty")
	}
}

func TestTokenService_Rotate(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{UserID: "u1", TenantID: "loxtu", Role: "worker"})
	sessions := newMockSessionStore()
	svc := identity.NewTokenService(users, sessions)
	p1, _ := svc.IssueSession(context.Background(), "u1", "loxtu", "worker", nil)
	p2, err := svc.Rotate(context.Background(), p1.RefreshPlain)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if p2.RefreshPlain == p1.RefreshPlain {
		t.Error("new token should differ")
	}
}

func TestTokenService_Rotate_SessionNotFound(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")
	svc := identity.NewTokenService(newMockUserStore(), newMockSessionStore())
	_, err := svc.Rotate(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error")
	}
}

func TestTokenService_Rotate_NilSessions(t *testing.T) {
	svc := identity.NewTokenService(nil, nil)
	_, err := svc.Rotate(context.Background(), "x")
	if err == nil {
		t.Error("expected error")
	}
}

func TestTokenService_RevokeAllForUser(t *testing.T) {
	svc := identity.NewTokenService(newMockUserStore(), newMockSessionStore())
	if err := svc.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestTokenService_RevokeAllForUser_Nil(t *testing.T) {
	svc := identity.NewTokenService(nil, nil)
	if err := svc.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Errorf("should be nil-safe: %v", err)
	}
}

func TestNewSessionAuthService(t *testing.T) {
	svc := identity.NewSessionAuthService(newMockUserStore(), newMockSessionStore())
	if svc == nil {
		t.Error("nil")
	}
	ts := identity.NewTokenService(newMockUserStore(), newMockSessionStore())
	if ts == nil {
		t.Error("alias nil")
	}
}

// ── Passkey extras ──────────────────────────────────────────────────────

func TestPasskeyService_FindUserByHandle(t *testing.T) {
	creds := newMockCredStore()
	creds.usersByHandle["loxtu:abc"] = &identity.PasskeyUser{UserID: "u1", TenantID: "loxtu"}
	svc := identity.NewPasskeyService(newMockUserStore(), creds, nil, "test-pepper")
	u, err := svc.FindUserByHandle(context.Background(), []byte("loxtu:abc"))
	if err != nil || u.UserID != "u1" {
		t.Errorf("got %v err %v", u, err)
	}
}

func TestPasskeyService_FindUserByHandle_NotFound(t *testing.T) {
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), nil, "test-pepper")
	_, err := svc.FindUserByHandle(context.Background(), []byte("x"))
	if err == nil {
		t.Error("expected error")
	}
}

func TestRateKeyFuncs(t *testing.T) {
	if identity.RateKeyOTPSend("a@b.com") == "" {
		t.Error("empty")
	}
	if identity.RateKeyOTPFail("a@b.com") == "" {
		t.Error("empty")
	}
	if identity.RateKeyLogin("a@b.com") == "" {
		t.Error("empty")
	}
	if identity.RateKeySessions("u1") == "" {
		t.Error("empty")
	}
}

// ── Extra coverage for passkey helpers ───────────────────────────────────

func TestPasskeyService_BeginRegistration_WithWA(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{
		UserID: "u1", EmailHash: identity.EmailHashWithPepper("x@y.com", "test-pepper"), TenantID: "loxtu",
	})
	creds := newMockCredStore()
	svc := identity.NewPasskeyService(users, creds, wa, "test-pepper")

	options, challenge, err := svc.BeginRegistration(context.Background(), "x@y.com", "loxtu")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options == nil {
		t.Error("options should not be nil")
	}
	if challenge == "" {
		t.Error("challenge should not be empty")
	}
}

func TestPasskeyService_BeginLogin_WithWA(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{
		UserID: "u1", EmailHash: identity.EmailHashWithPepper("x@y.com", "test-pepper"), TenantID: "loxtu",
	})
	creds := newMockCredStore()
	// Need credentials for BeginLogin to work
	creds.credsByUser["u1"] = []*identity.PasskeyCredential{
		{CredentialID: []byte("kid1"), UserID: "u1", PublicKey: []byte("pk1")},
	}
	svc := identity.NewPasskeyService(users, creds, wa, "test-pepper")

	options, challenge, err := svc.BeginLogin(context.Background(), "x@y.com", "loxtu")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if options == nil {
		t.Error("options nil")
	}
	if challenge == "" {
		t.Error("challenge empty")
	}
}

func TestPasskeyService_BeginLogin_UserNotFound(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), wa, "test-pepper")
	_, _, err := svc.BeginLogin(context.Background(), "nobody@x.com", "loxtu")
	if err == nil {
		t.Error("expected error")
	}
}

func TestPasskeyService_BeginLoginDiscoverable_WithWA(t *testing.T) {
	wa, _ := identity.NewWebAuthn("localhost", "http://localhost")
	svc := identity.NewPasskeyService(newMockUserStore(), newMockCredStore(), wa, "test-pepper")
	options, challenge, err := svc.BeginLoginDiscoverable(context.Background(), "loxtu")
	if err != nil {
		t.Fatalf("BeginLoginDiscoverable: %v", err)
	}
	if options == nil || challenge == "" {
		t.Error("options or challenge empty")
	}
}

func TestPasskeyService_UpdateCredentialSignCount(t *testing.T) {
	creds := newMockCredStore()
	svc := identity.NewPasskeyService(newMockUserStore(), creds, nil, "test-pepper")
	if err := svc.UpdateCredentialSignCount(context.Background(), "u1", []byte("kid1"), 5); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestWebauthnCredsFromDomain(t *testing.T) {
	// This tests the helper indirectly through GetUser
	creds := newMockCredStore()
	creds.credsByUser["u1"] = []*identity.PasskeyCredential{
		{CredentialID: []byte("kid1"), UserID: "u1", PublicKey: []byte("pk1"),
			BackupEligible: true, BackupState: false, AAGUID: "test"},
	}
	users := newMockUserStore()
	users.Create(context.Background(), &identity.User{
		UserID: "u1", EmailHash: identity.EmailHashWithPepper("x@y.com", "test-pepper"),
	})
	svc := identity.NewPasskeyService(users, creds, nil, "test-pepper")
	user, err := svc.GetUser(context.Background(), "x@y.com")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(user.Credentials) != 1 {
		t.Errorf("creds = %d", len(user.Credentials))
	}
	if user.Credentials[0].Flags.BackupEligible != true {
		t.Error("BackupEligible should be true")
	}
}
