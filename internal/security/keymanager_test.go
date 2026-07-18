package security

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"
)

func TestKeyManager_Roundtrip(t *testing.T) {
	kek, _ := GenerateDEK()
	t.Setenv("LOXTU_DATA_KEY", base64.StdEncoding.EncodeToString(kek))

	km, err := NewEnvKeyManager()
	if err != nil {
		t.Fatalf("NewEnvKeyManager: %v", err)
	}

	dek, encDEK, err := km.GenerateAndEncryptDEK()
	if err != nil {
		t.Fatalf("GenerateAndEncryptDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("DEK should be 32 bytes, got %d", len(dek))
	}
	if len(encDEK) == 0 {
		t.Fatal("encrypted DEK should not be empty")
	}

	decDEK, err := km.DecryptDEK(encDEK)
	if err != nil {
		t.Fatalf("DecryptDEK: %v", err)
	}
	if !bytes.Equal(dek, decDEK) {
		t.Error("KeyManager roundtrip failed: decrypted DEK != original")
	}
}

func TestNewEnvKeyManager_MissingKey(t *testing.T) {
	os.Unsetenv("LOXTU_DATA_KEY")
	_, err := NewEnvKeyManager()
	if err == nil {
		t.Error("expected error when LOXTU_DATA_KEY is not set")
	}
}

func TestNewEnvKeyManager_InvalidBase64(t *testing.T) {
	t.Setenv("LOXTU_DATA_KEY", "not-valid-base64!!!")
	_, err := NewEnvKeyManager()
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestNewEnvKeyManager_WrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	t.Setenv("LOXTU_DATA_KEY", short)
	_, err := NewEnvKeyManager()
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestNewEnvKeyManager_ValidKey(t *testing.T) {
	kek, _ := GenerateDEK()
	t.Setenv("LOXTU_DATA_KEY", base64.StdEncoding.EncodeToString(kek))
	km, err := NewEnvKeyManager()
	if err != nil {
		t.Fatalf("NewEnvKeyManager should succeed with valid 32-byte key: %v", err)
	}
	if km == nil {
		t.Fatal("KeyManager should not be nil")
	}
}
