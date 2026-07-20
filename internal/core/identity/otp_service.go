package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"
)

const (
	otpLength   = 6
	otpLifetime = 3 * time.Minute
	maxAttempts = 3
)

// GenerateCode produces a cryptographically random numeric code of otpLength digits.
func GenerateCode() (string, error) {
	code := make([]byte, otpLength)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generate otp: %w", err)
		}
		code[i] = byte('0') + byte(n.Int64())
	}
	return string(code), nil
}

// OTPService generates, persists and verifies OTPs via OTPStore + OTPSender.
type OTPService struct {
	sender OTPSender
	store  OTPStore
}

// NewOTPService constructs an OTP service with DB-backed storage.
// sender may be nil (dev stdout fallback).
func NewOTPService(sender OTPSender, store OTPStore) *OTPService {
	return &OTPService{sender: sender, store: store}
}

// sha256Hex returns hex-encoded SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Send creates and stores an OTP keyed by userIDHash, sends the code to email.
// userIDHash is the storage key (otp_codes:[userIDHash]) — no PII in the DB key.
func (s *OTPService) Send(ctx context.Context, email, userIDHash string) error {
	code, err := GenerateCode()
	if err != nil {
		return err
	}

	codeHash := sha256Hex(code)
	expiresAt := time.Now().Add(otpLifetime)

	if s.store != nil {
		if err := s.store.Save(ctx, userIDHash, codeHash, expiresAt); err != nil {
			return fmt.Errorf("save otp: %w", err)
		}
	}

	if s.sender != nil {
		notif := OTPNotification{
			Notification: Notification{RecipientID: email},
			Code:         code,
			Expiry:       otpLifetime,
		}
		if err := s.sender.SendOTP(ctx, notif); err != nil {
			log.Printf("[otp] ERROR sending OTP: %v", err)
			return fmt.Errorf("send OTP: %w", err)
		}
	} else {
		// Dev fallback — never ship to prod without a sender.
		fmt.Printf("[OTP] %s -> %s\n", email, code)
	}

	return nil
}

// Verify checks the OTP code for the given userIDHash (key = otp_codes:[userIDHash]).
// On success the OTP is consumed (single-use). Returns true if valid.
func (s *OTPService) Verify(ctx context.Context, userIDHash, code string) (bool, error) {
	if s.store == nil {
		return false, fmt.Errorf("otp store not configured")
	}

	storedHash, attempts, expiresAt, err := s.store.Get(ctx, userIDHash)
	if err != nil {
		return false, nil // not found → treat as invalid
	}

	// Expiry check (lazy — DB may have stale records)
	if time.Now().After(expiresAt) {
		_ = s.store.Delete(ctx, userIDHash)
		return false, nil
	}

	// Attempt limit
	if attempts >= maxAttempts {
		_ = s.store.Delete(ctx, userIDHash)
		return false, nil
	}

	// Increment attempts (track failed attempts)
	_ = s.store.IncrementAttempts(ctx, userIDHash)

	// Constant-time comparison would be better, but for 6-digit OTP this is acceptable
	if storedHash != sha256Hex(code) {
		return false, nil
	}

	// Success — consume the OTP
	_ = s.store.Delete(ctx, userIDHash)
	return true, nil
}
