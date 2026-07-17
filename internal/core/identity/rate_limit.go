package identity

import (
	"context"
	"time"
)

// RateLimiter enforces attempt/quota policies identified by opaque keys.
//
// Design:
//   - Port lives in core (client rule). Adapters: memory, future Redis.
//   - Window = 0 means a permanent quota (counter never expires by time).
//   - Allow consumes one unit when under limit; returns false when exhausted.
//   - Keys are free-form (e.g. "otp:send:user@x", "sessions:users:abc").
//   - No QuotaManager type — permanent quotas use Window=0 on the same port.
//
// Implemented by adapters/ratelimit.
type RateLimiter interface {
	// Allow reports whether the action is permitted and records one attempt under policy.
	Allow(ctx context.Context, key string, policy RateLimitPolicy) (bool, error)
	// Reset clears counters for key (e.g. after successful OTP verify).
	Reset(ctx context.Context, key string) error
	// GetRemaining returns how many attempts remain in the current window (0 = blocked/exhausted).
	GetRemaining(ctx context.Context, key string, policy RateLimitPolicy) (int, error)
}

// RateLimitPolicy is a named limit domain rules can share.
type RateLimitPolicy struct {
	MaxAttempts int
	// Window is the sliding/fixed window for the counter.
	// Zero means permanent quota (no time-based cleanup).
	Window      time.Duration
	Description string
}

// Predefined policies (business rules).
var (
	// PolicyOTP — OTP-related sends/verify attempts.
	PolicyOTP = RateLimitPolicy{
		MaxAttempts: 5,
		Window:      10 * time.Minute,
		Description: "OTP verification attempts",
	}
	// PolicyLogin — general login surface / credential thrash.
	PolicyLogin = RateLimitPolicy{
		MaxAttempts: 10,
		Window:      15 * time.Minute,
		Description: "Login attempts",
	}
	// PolicyRegistration — progressive signup / invite abuse.
	PolicyRegistration = RateLimitPolicy{
		MaxAttempts: 30,
		Window:      time.Hour,
		Description: "Registration attempts",
	}
	// PolicyMaxSessions — one active refresh session per user (Window=0 permanent).
	PolicyMaxSessions = RateLimitPolicy{
		MaxAttempts: 1,
		Window:      0,
		Description: "Maximum active sessions per user",
	}
)

// Key helpers for consistent key composition (optional; callers may format freely).
func RateKeyOTPSend(email string) string  { return "otp:send:" + email }
func RateKeyOTPFail(email string) string  { return "otp:fail:" + email }
func RateKeyLogin(email string) string    { return "login:" + email }
func RateKeySessions(actorID string) string { return "sessions:" + actorID }
