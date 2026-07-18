// Package security provides cryptographic primitives for LOXTU:
// envelope encryption (KEK/DEK), PII hashing, and PIN hashing.
// No external dependencies beyond std crypto + golang.org/x/crypto.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ── Email Hashing ────────────────────────────────────────────────────────

// HashEmail returns SHA-256(lowercase(trim(email)) + pepper).
// Used for lookup — never stored as plaintext email.
func HashEmail(email, pepper string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email)) + pepper))
	return hex.EncodeToString(h[:])
}

// MaskEmail returns "v***v@loxtu.com" for UI/logs.
// Duplicate of httputil.MaskEmail but avoids import cycle in security package.
func MaskEmail(email string) string {
	parts := strings.SplitN(strings.TrimSpace(email), "@", 2)
	if len(parts) != 2 || len(parts[0]) == 0 {
		return "***"
	}
	local := parts[0]
	if len(local) <= 2 {
		return local[:1] + "***@" + parts[1]
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + parts[1]
}

// ── Envelope Encryption (AES-256-GCM) ───────────────────────────────────

// GenerateDEK creates a random 32-byte Data Encryption Key.
func GenerateDEK() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	return b, nil
}

// EncryptPII encrypts plaintext with AES-256-GCM using the DEK.
// Returns nonce || ciphertext (nonce is 12 bytes prepended).
func EncryptPII(plaintext string, dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("empty DEK")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// DecryptPII decrypts AES-256-GCM ciphertext (nonce || ciphertext) with the DEK.
func DecryptPII(ciphertext, dek []byte) (string, error) {
	if len(dek) == 0 {
		return "", fmt.Errorf("empty DEK")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err)
	}
	return string(plaintext), nil
}

// ── Key Encryption Key (KEK) operations ─────────────────────────────────

// EncryptDEK encrypts the DEK with the KEK (AES-256-GCM).
// Used when storing encrypted_dek in the users table.
func EncryptDEK(dek, kek []byte) ([]byte, error) {
	return EncryptPII(base64.StdEncoding.EncodeToString(dek), kek)
}

// DecryptDEK decrypts the DEK from encrypted_dek using the KEK.
// Returns the raw 32-byte DEK.
func DecryptDEK(encryptedDEK, kek []byte) ([]byte, error) {
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

// ── PIN Hashing (Argon2id) ──────────────────────────────────────────────

// HashPIN returns an Argon2id hash of the PIN with the given salt.
// Format: base64(argon2id(pin, salt, 3 iterations, 64MB, 4 threads, 32 bytes)).
func HashPIN(pin string, salt []byte) string {
	hash := argon2.IDKey([]byte(pin), salt, 3, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

// GenerateSalt creates a random 16-byte salt for PIN hashing.
func GenerateSalt() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return b, nil
}
