package identity_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// Deterministic hash: user_id_hash = hex(SHA-256(userID))
func userIDHash(userID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(userID)))
}

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
	// sub = user_id_hash (SHA-256 of userID), not raw UUID
	expectedHash := userIDHash("user-uuid-123")
	if claims.Subject != expectedHash {
		t.Errorf("Subject = %q, want %q (user_id_hash)", claims.Subject, expectedHash)
	}
	if claims.UserIDHash != expectedHash {
		t.Errorf("UserIDHash = %q, want %q", claims.UserIDHash, expectedHash)
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
	// No raw UUID in claims
	if claims.UserIDHash == "" {
		t.Error("UserIDHash should not be empty")
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

// TestIssueAccessToken_DeterministicHash verifies that the same userID
// always produces the same user_id_hash (sub claim) — no salt, no randomness.
func TestIssueAccessToken_DeterministicHash(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	userID := "e995330d-333d-4d70-8912-ec5b759a0de2"

	// Generate two tokens with the same userID
	tok1, err := identity.IssueAccessToken(userID, "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := identity.IssueAccessToken(userID, "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Different signing time → different token body → different tokens
	// Tokens might be identical if created in the same nanosecond — that's OK.
	// The critical invariant: hash values must be identical regardless of iat.

	// But the hash values must be identical
	c1, _ := identity.ValidateAccessToken(tok1)
	c2, _ := identity.ValidateAccessToken(tok2)
	if c1.Subject != c2.Subject {
		t.Errorf("Subject hash differs: %q vs %q", c1.Subject, c2.Subject)
	}
	if c1.UserIDHash != c2.UserIDHash {
		t.Errorf("UserIDHash differs: %q vs %q", c1.UserIDHash, c2.UserIDHash)
	}

	// Verify the hash is deterministic SHA-256
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(userID)))
	if c1.UserIDHash != expected {
		t.Errorf("UserIDHash = %q, want %q (SHA-256 of userID, no salt)", c1.UserIDHash, expected)
	}
}

// TestIssueAccessToken_NoRawUUID verifies that the raw user UUID is never
// written to the JWT in plaintext (PII protection).
func TestIssueAccessToken_NoRawUUID(t *testing.T) {
	t.Setenv("LOXTU_JWT_SECRET", "test-secret-for-unit-tests-32bytes!")

	userID := "e995330d-333d-4d70-8912-ec5b759a0de2"
	tok, err := identity.IssueAccessToken(userID, "loxtu", "worker", nil, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := identity.ValidateAccessToken(tok)
	if err != nil {
		t.Fatal(err)
	}

	// Subject must be the hash, not the raw UUID
	if claims.Subject == userID {
		t.Error("Subject contains raw UUID — PII leak!")
	}
	// UserIDHash must be the hash, not the raw UUID
	if claims.UserIDHash == userID {
		t.Error("UserIDHash contains raw UUID — PII leak!")
	}
	// TenantID is NOT PII, should be readable
	if claims.TenantID != "loxtu" {
		t.Errorf("TenantID = %q, want loxtu", claims.TenantID)
	}
}