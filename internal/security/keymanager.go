package security

import (
	"encoding/base64"
	"fmt"
	"os"
)

// KeyManager handles KEK → DEK envelope encryption.
// KEK (Key Encryption Key) lives in LOXTU_DATA_KEY env var.
// DEK (Data Encryption Key) is stored per-user in users.encrypted_dek.
type KeyManager interface {
	// EncryptDEK encrypts a DEK with the KEK for storage.
	EncryptDEK(dek []byte) ([]byte, error)
	// DecryptDEK decrypts a stored DEK using the KEK.
	DecryptDEK(encryptedDEK []byte) ([]byte, error)
	// GenerateAndEncryptDEK creates a new DEK and returns (dek, encryptedDEK, error).
	GenerateAndEncryptDEK() (dek, encryptedDEK []byte, err error)
}

// EnvKeyManager reads KEK from LOXTU_DATA_KEY environment variable.
type EnvKeyManager struct {
	kek []byte
}

// NewEnvKeyManager creates a KeyManager from the LOXTU_DATA_KEY env var.
// Returns error if the key is missing or not 32 bytes.
func NewEnvKeyManager() (*EnvKeyManager, error) {
	kekB64 := os.Getenv("LOXTU_DATA_KEY")
	if kekB64 == "" {
		return nil, fmt.Errorf("LOXTU_DATA_KEY is not set")
	}
	kek, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		return nil, fmt.Errorf("LOXTU_DATA_KEY is not valid base64: %w", err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("LOXTU_DATA_KEY must be 32 bytes (got %d)", len(kek))
	}
	return &EnvKeyManager{kek: kek}, nil
}

var _ KeyManager = (*EnvKeyManager)(nil)

// EncryptDEK encrypts a DEK with the KEK (AES-256-GCM).
func (m *EnvKeyManager) EncryptDEK(dek []byte) ([]byte, error) {
	return encryptDEKWithKEK(dek, m.kek)
}

// DecryptDEK decrypts a stored DEK using the KEK.
func (m *EnvKeyManager) DecryptDEK(encryptedDEK []byte) ([]byte, error) {
	return decryptDEKWithKEK(encryptedDEK, m.kek)
}

// GenerateAndEncryptDEK creates a new DEK and returns (dek, encryptedDEK, error).
func (m *EnvKeyManager) GenerateAndEncryptDEK() (dek, encryptedDEK []byte, err error) {
	dek, err = GenerateDEK()
	if err != nil {
		return nil, nil, fmt.Errorf("generate DEK: %w", err)
	}
	encryptedDEK, err = m.EncryptDEK(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt DEK: %w", err)
	}
	return dek, encryptedDEK, nil
}

// encryptDEKWithKEK encrypts the DEK with the KEK (AES-256-GCM).
func encryptDEKWithKEK(dek, kek []byte) ([]byte, error) {
	return EncryptPII(base64.StdEncoding.EncodeToString(dek), kek)
}

// decryptDEKWithKEK decrypts the DEK from encrypted_dek using the KEK.
func decryptDEKWithKEK(encryptedDEK, kek []byte) ([]byte, error) {
	b64, err := DecryptPII(encryptedDEK, kek)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode DEK base64: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK length: %d", len(dek))
	}
	return dek, nil
}
