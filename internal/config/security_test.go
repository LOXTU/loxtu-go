package config

import (
	"encoding/base64"
	"testing"

	"github.com/loxtu/loxtu-go/internal/security"
)

func TestSecurityFromEnv_FailFast_NoKey(t *testing.T) {
	t.Setenv("LOXTU_DATA_KEY", "")
	t.Setenv("LOXTU_HASH_PEPPER", "some-pepper")
	_, err := SecurityFromEnv()
	if err == nil {
		t.Error("expected error when LOXTU_DATA_KEY is empty")
	}
}

func TestSecurityFromEnv_FailFast_NoPepper(t *testing.T) {
	kek, _ := security.GenerateDEK()
	t.Setenv("LOXTU_DATA_KEY", base64.StdEncoding.EncodeToString(kek))
	t.Setenv("LOXTU_HASH_PEPPER", "")
	_, err := SecurityFromEnv()
	if err == nil {
		t.Error("expected error when LOXTU_HASH_PEPPER is empty")
	}
}

func TestSecurityFromEnv_FailFast_InvalidBase64(t *testing.T) {
	t.Setenv("LOXTU_DATA_KEY", "not-base64!!!")
	t.Setenv("LOXTU_HASH_PEPPER", "pepper")
	_, err := SecurityFromEnv()
	if err == nil {
		t.Error("expected error for invalid base64 key")
	}
}

func TestSecurityFromEnv_FailFast_WrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	t.Setenv("LOXTU_DATA_KEY", short)
	t.Setenv("LOXTU_HASH_PEPPER", "pepper")
	_, err := SecurityFromEnv()
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestEnvLoading(t *testing.T) {
	kek, _ := security.GenerateDEK()
	pepper := "test-pepper-value"
	t.Setenv("LOXTU_DATA_KEY", base64.StdEncoding.EncodeToString(kek))
	t.Setenv("LOXTU_HASH_PEPPER", pepper)

	cfg, err := SecurityFromEnv()
	if err != nil {
		t.Fatalf("SecurityFromEnv: %v", err)
	}
	if len(cfg.KEK) != 32 {
		t.Errorf("KEK should be 32 bytes, got %d", len(cfg.KEK))
	}
	if cfg.HashPepper != pepper {
		t.Errorf("HashPepper = %q, want %q", cfg.HashPepper, pepper)
	}

	// Verify KEK roundtrip works
	km, err := security.NewEnvKeyManager()
	if err != nil {
		t.Fatalf("NewEnvKeyManager: %v", err)
	}
	dek, enc, err := km.GenerateAndEncryptDEK()
	if err != nil {
		t.Fatalf("GenerateAndEncryptDEK: %v", err)
	}
	dec, err := km.DecryptDEK(enc)
	if err != nil {
		t.Fatalf("DecryptDEK: %v", err)
	}
	if string(dek) != string(dec) {
		t.Error("KEK roundtrip failed")
	}
}

func TestSurrealDBFromEnv_Defaults(t *testing.T) {
	cfg := SurrealDBFromEnv()
	if cfg.Endpoint == "" {
		t.Error("default Endpoint should not be empty")
	}
	if cfg.Namespace == "" {
		t.Error("default Namespace should not be empty")
	}
	if cfg.Database == "" {
		t.Error("default Database should not be empty")
	}
	if cfg.MaxConns <= 0 {
		t.Error("default MaxConns should be positive")
	}
}

func TestSMTPFromEnv_Defaults(t *testing.T) {
	cfg := SMTPFromEnv()
	if cfg.Host == "" {
		t.Error("default Host should not be empty")
	}
	if cfg.Port <= 0 {
		t.Error("default Port should be positive")
	}
}

func TestSurrealDBFromEnv_Custom(t *testing.T) {
	t.Setenv("SURREALDB_ENDPOINT", "ws://custom:9999/rpc")
	t.Setenv("SURREALDB_NS", "myns")
	t.Setenv("SURREALDB_POOL_SIZE", "5")
	cfg := SurrealDBFromEnv()
	if cfg.Endpoint != "ws://custom:9999/rpc" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.Namespace != "myns" {
		t.Errorf("Namespace = %q", cfg.Namespace)
	}
	if cfg.MaxConns != 5 {
		t.Errorf("MaxConns = %d", cfg.MaxConns)
	}
}
