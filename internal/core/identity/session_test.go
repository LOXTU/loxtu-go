package identity_test

import (
	"testing"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

func TestIssueAccessToken_TenantPolicy(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	// Default TTL
	tok1, err := identity.IssueAccessToken("user-123", "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken default: %v", err)
	}
	if tok1 == "" {
		t.Error("token should not be empty")
	}

	// Custom TTL (e.g. Delta wants 6 minutes)
	tok2, err := identity.IssueAccessToken("user-123", "delta", "worker", nil, 6*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken custom: %v", err)
	}
	if tok2 == "" {
		t.Error("token should not be empty")
	}
	// Tokens should be different (different expiry in claims)
	if tok1 == tok2 {
		t.Error("different TTL should produce different tokens")
	}
}

func TestValidateAccessToken_Roundtrip(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	tok, err := identity.IssueAccessToken("user-uuid-123", "loxtu", "admin", []string{"manage"}, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	claims, err := identity.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-uuid-123" {
		t.Errorf("UserID = %q", claims.UserID)
	}
	if claims.TenantID != "loxtu" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q", claims.Role)
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "manage" {
		t.Errorf("Permissions = %v", claims.Permissions)
	}
}

func TestValidateAccessToken_Invalid(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	_, err := identity.ValidateAccessToken("not-a-valid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestIssueTokens_Roundtrip(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	pair, err := identity.IssueTokens("user-1", "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueTokens: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken empty")
	}
	if pair.RefreshPlain == "" {
		t.Error("RefreshPlain empty")
	}
	if pair.RefreshHash == "" {
		t.Error("RefreshHash empty")
	}
	if pair.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
	// Refresh hash should be deterministic
	hash := identity.HashToken(pair.RefreshPlain)
	if hash != pair.RefreshHash {
		t.Errorf("HashToken mismatch: %s != %s", hash, pair.RefreshHash)
	}
}

func TestIssueRefreshToken_Unique(t *testing.T) {
	plain1, hash1, _ := identity.IssueRefreshToken()
	plain2, hash2, _ := identity.IssueRefreshToken()
	if plain1 == plain2 {
		t.Error("two refresh tokens should be different")
	}
	if hash1 == hash2 {
		t.Error("two refresh hashes should be different")
	}
	if len(plain1) != 64 { // 32 bytes hex
		t.Errorf("plain length = %d, want 64", len(plain1))
	}
}
