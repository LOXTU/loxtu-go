package identity

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

const (
	otpLength    = 6
	otpLifetime  = 3 * time.Minute
	maxAttempts  = 3
	cleanupEvery = 30 * time.Second
)

// OTPData is an in-memory one-time password record (domain TTL / attempts).
type OTPData struct {
	Email     string
	Code      string
	ExpiresAt time.Time
	Attempts  int
}

// OTPService generates, stores and verifies OTPs; delivery via OTPSender.
type OTPService struct {
	sender OTPSender

	mu   sync.RWMutex
	otps map[string]*OTPData
}

// NewOTPService constructs an OTP service. sender may be nil (dev stdout fallback).
func NewOTPService(sender OTPSender) *OTPService {
	s := &OTPService{
		sender: sender,
		otps:   make(map[string]*OTPData),
	}
	go s.cleanupLoop()
	return s
}

func (s *OTPService) cleanupLoop() {
	for range time.NewTicker(cleanupEvery).C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.otps {
			if now.After(v.ExpiresAt) {
				delete(s.otps, k)
			}
		}
		s.mu.Unlock()
	}
}

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

// Send creates and stores an OTP for email, then delivers via OTPSender.
func (s *OTPService) Send(ctx context.Context, email string) (*OTPData, error) {
	code, err := GenerateCode()
	if err != nil {
		return nil, err
	}

	otp := &OTPData{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(otpLifetime),
		Attempts:  0,
	}

	s.mu.Lock()
	s.otps[email] = otp
	s.mu.Unlock()

	if s.sender != nil {
		notif := OTPNotification{
			Notification: Notification{RecipientID: email},
			Code:         code,
			Expiry:       otpLifetime,
		}
		if err := s.sender.SendOTP(ctx, notif); err != nil {
			log.Printf("[otp] ERROR sending OTP: %v", err)
			return nil, fmt.Errorf("send OTP: %w", err)
		}
	} else {
		// Dev fallback — never ship to prod without a sender.
		fmt.Printf("[OTP] %s -> %s\n", email, code)
	}

	return otp, nil
}

// Verify checks the OTP code for the given email (maxAttempts, TTL).
// On success the OTP is consumed (single-use).
func (s *OTPService) Verify(email, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	otp, ok := s.otps[email]
	if !ok {
		return false
	}

	if time.Now().After(otp.ExpiresAt) {
		delete(s.otps, email)
		return false
	}

	otp.Attempts++
	if otp.Attempts > maxAttempts {
		delete(s.otps, email)
		return false
	}

	if otp.Code != code {
		return false
	}

	delete(s.otps, email)
	return true
}
