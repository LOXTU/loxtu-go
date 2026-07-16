package auth

import "time"

// OTPData represents an active one-time password.
type OTPData struct {
	Email     string
	Code      string
	ExpiresAt time.Time
	Attempts  int
}

// SendOTPRequest is the payload for requesting an OTP.
type SendOTPRequest struct {
	Email string `json:"email"`
}

// VerifyOTPRequest is the payload for verifying an OTP.
type VerifyOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}