package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashEmail(t *testing.T) {
	pepper := "test-pepper-123"
	email := "Vitaly.Semenov@Loxtu.COM"

	h1 := HashEmail(email, pepper)
	h2 := HashEmail(email, pepper)
	h3 := HashEmail(email, "different-pepper")
	h4 := HashEmail(strings.ToLower(email), pepper)

	// Same email + same pepper = same hash
	if h1 != h2 {
		t.Errorf("same inputs should produce same hash, got %s != %s", h1, h2)
	}
	// Same email + different pepper = different hash
	if h1 == h3 {
		t.Errorf("different pepper should produce different hash")
	}
	// Case-insensitive (lowercased before hashing)
	if h1 != h4 {
		t.Errorf("case-insensitive: %s vs %s", h1, h4)
	}
	// Non-empty
	if h1 == "" {
		t.Error("hash should not be empty")
	}
	// 64 hex chars (SHA-256)
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
}

func TestEncryptDecryptPII_Roundtrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	plaintext := "vitaly.semenov@loxtu.com"

	ct, err := EncryptPII(plaintext, dek)
	if err != nil {
		t.Fatalf("EncryptPII: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	got, err := DecryptPII(ct, dek)
	if err != nil {
		t.Fatalf("DecryptPII: %v", err)
	}
	if got != plaintext {
		t.Errorf("roundtrip failed: want %q, got %q", plaintext, got)
	}
}

func TestEncryptPII_UniqueNonce(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	plaintext := "same-plaintext"

	ct1, err := EncryptPII(plaintext, dek)
	if err != nil {
		t.Fatalf("EncryptPII #1: %v", err)
	}
	ct2, err := EncryptPII(plaintext, dek)
	if err != nil {
		t.Fatalf("EncryptPII #2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext with same DEK must produce different ciphertext (unique nonce)")
	}
}

func TestEncryptPII_EmptyDEK(t *testing.T) {
	_, err := EncryptPII("test", nil)
	if err == nil {
		t.Error("expected error for nil DEK")
	}
	_, err = EncryptPII("test", []byte{})
	if err == nil {
		t.Error("expected error for empty DEK")
	}
}

func TestDecryptPII_WrongDEK(t *testing.T) {
	dek1, _ := GenerateDEK()
	dek2, _ := GenerateDEK()

	ct, err := EncryptPII("secret", dek1)
	if err != nil {
		t.Fatalf("EncryptPII: %v", err)
	}
	_, err = DecryptPII(ct, dek2)
	if err == nil {
		t.Error("expected error when decrypting with wrong DEK")
	}
}

func TestDecryptPII_TruncatedCiphertext(t *testing.T) {
	dek, _ := GenerateDEK()
	_, err := DecryptPII([]byte{1, 2, 3}, dek)
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestHashPIN(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	pin := "1234"

	h1 := HashPIN(pin, salt)
	h2 := HashPIN(pin, salt)

	if h1 == "" {
		t.Error("hash should not be empty")
	}
	if h1 != h2 {
		t.Errorf("same PIN + same salt should produce same hash")
	}
	// Different salt → different hash
	salt2, _ := GenerateSalt()
	h3 := HashPIN(pin, salt2)
	if h1 == h3 {
		t.Error("different salt should produce different hash")
	}
}

func TestGenerateSalt(t *testing.T) {
	s1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	s2, _ := GenerateSalt()
	if len(s1) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(s1))
	}
	if bytes.Equal(s1, s2) {
		t.Error("two calls should produce different salts")
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"vitaly@loxtu.com", "v***y@loxtu.com"},
		{"ab@loxtu.com", "a***@loxtu.com"},
		{"a@loxtu.com", "a***@loxtu.com"},
		{"", "***"},
		{"invalid", "***"},
		{"user@example.org", "u***r@example.org"},
	}
	for _, tt := range tests {
		got := MaskEmail(tt.input)
		if got != tt.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEncryptDEK_Roundtrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	kek, _ := GenerateDEK() // use random 32-byte key as KEK

	encDEK, err := EncryptDEK(dek, kek)
	if err != nil {
		t.Fatalf("EncryptDEK: %v", err)
	}
	decDEK, err := DecryptDEK(encDEK, kek)
	if err != nil {
		t.Fatalf("DecryptDEK: %v", err)
	}
	if !bytes.Equal(dek, decDEK) {
		t.Error("DEK roundtrip failed: decrypted DEK != original")
	}
}

func TestDecryptDEK_InvalidLength(t *testing.T) {
	kek, _ := GenerateDEK()
	// Encrypt a non-DEK value
	ct, _ := EncryptPII("not-a-dek", kek)
	_, err := DecryptDEK(ct, kek)
	if err == nil {
		t.Error("expected error for invalid DEK length")
	}
}

func TestDecryptPII_TamperedCiphertext(t *testing.T) {
	dek, _ := GenerateDEK()
	ct, err := EncryptPII("sensitive-data", dek)
	if err != nil {
		t.Fatalf("EncryptPII: %v", err)
	}

	// Tamper with one byte in the ciphertext body (after 12-byte nonce).
	// GCM authentication tag should catch this.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	if len(tampered) > 14 {
		tampered[14] ^= 0xFF // flip all bits in one byte
	} else {
		t.Fatal("ciphertext too short to tamper")
	}

	result, err := DecryptPII(tampered, dek)
	if err == nil {
		t.Errorf("expected GCM authentication error for tampered ciphertext, got plaintext: %q", result)
	}
}

func TestMaskEmail_EdgeCases(t *testing.T) {
	cases := []string{
		"a@b.com",
		"@loxtu.com",
		"",
		"noatsign",
		"   ",
		"@@@",
	}
	for _, input := range cases {
		// Must not panic
		got := MaskEmail(input)
		if got == "" {
			t.Errorf("MaskEmail(%q) returned empty string", input)
		}
	}
}

func TestGenerateDEK_Length(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("DEK length = %d, want 32", len(dek))
	}
}

func TestGenerateSalt_Length(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("salt length = %d, want 16", len(salt))
	}
}
