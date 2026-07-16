package auth

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

const (
	otpLength    = 6
	otpLifetime  = 3 * time.Minute
	maxAttempts  = 3
	cleanupEvery = 30 * time.Second
)

type Store struct {
	mu   sync.RWMutex
	otps map[string]*OTPData
}

var global = &Store{otps: make(map[string]*OTPData)}

func init() {
	go func() {
		for range time.NewTicker(cleanupEvery).C {
			global.mu.Lock()
			now := time.Now()
			for k, v := range global.otps {
				if now.After(v.ExpiresAt) {
					delete(global.otps, k)
				}
			}
			global.mu.Unlock()
		}
	}()
}

// generateCode produces a cryptographically random numeric code of otpLength digits.
func generateCode() (string, error) {
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

// EmailClient is set from main.go to enable real SMTP delivery.
var EmailClient interface {
	SendOTP(to, code string) error
}

// Send creates and stores an OTP for the given email.
// If EmailClient is set, sends via SMTP; otherwise falls back to stdout.
func Send(email string) (*OTPData, error) {
	code, err := generateCode()
	if err != nil {
		return nil, err
	}

	otp := &OTPData{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(otpLifetime),
		Attempts:  0,
	}

	global.mu.Lock()
	global.otps[email] = otp
	global.mu.Unlock()

	// Send via email client (SMTP or dev fallback)
	if EmailClient != nil {
		if err := EmailClient.SendOTP(email, code); err != nil {
			log.Printf("[otp] ERROR sending OTP to %s: %v", mw.MaskEmail(email), err)
			return nil, fmt.Errorf("send OTP: %w", err)
		}
	} else {
		fmt.Printf("[OTP] %s -> %s\n", email, code)
	}

	return otp, nil
}

// Verify checks the OTP code for the given email.
func Verify(email, code string) bool {
	global.mu.Lock()
	defer global.mu.Unlock()

	otp, ok := global.otps[email]
	if !ok {
		return false
	}

	if time.Now().After(otp.ExpiresAt) {
		delete(global.otps, email)
		return false
	}

	otp.Attempts++
	if otp.Attempts > maxAttempts {
		delete(global.otps, email)
		return false
	}

	if otp.Code != code {
		return false
	}

	delete(global.otps, email)
	return true
}