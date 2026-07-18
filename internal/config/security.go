package config

import (
	"encoding/base64"
	"fmt"
	"os"
)

// SecurityConfig holds cryptographic keys loaded from ENV.
type SecurityConfig struct {
	// KEK is the Key Encryption Key (32 bytes, decoded from base64 env).
	// Used to encrypt/decrypt per-user DEKs.
	KEK []byte
	// HashPepper is the pepper for email hashing (SHA-256).
	HashPepper string
}

// SecurityFromEnv loads LOXTU_DATA_KEY and LOXTU_HASH_PEPPER.
// Returns error if either is missing or invalid.
func SecurityFromEnv() (SecurityConfig, error) {
	kekB64 := os.Getenv("LOXTU_DATA_KEY")
	if kekB64 == "" {
		return SecurityConfig{}, fmt.Errorf("LOXTU_DATA_KEY is required (base64-encoded 32-byte AES-256 key)")
	}
	kek, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		return SecurityConfig{}, fmt.Errorf("LOXTU_DATA_KEY is not valid base64: %w", err)
	}
	if len(kek) != 32 {
		return SecurityConfig{}, fmt.Errorf("LOXTU_DATA_KEY must be 32 bytes (got %d)", len(kek))
	}

	pepper := os.Getenv("LOXTU_HASH_PEPPER")
	if pepper == "" {
		return SecurityConfig{}, fmt.Errorf("LOXTU_HASH_PEPPER is required")
	}

	return SecurityConfig{KEK: kek, HashPepper: pepper}, nil
}
