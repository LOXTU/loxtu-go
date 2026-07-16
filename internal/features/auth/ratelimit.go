package auth

import (
	"sync"
	"time"
)

// ── Config ──

const (
	maxFailsBeforeBlock = 5
	blockDuration       = 5 * time.Minute
	failWindow          = 5 * time.Minute
	maxSendsPerWindow   = 3
	sendWindow          = 5 * time.Minute
	cleanupInterval     = 1 * time.Minute
)

// ── In-memory fail & send tracker ──

type failEntry struct {
	Count        int
	WindowStart  time.Time
	BlockedUntil time.Time
	SendCount    int
	SendStart    time.Time
	mu           sync.Mutex
}

// RateLimiter tracks OTP verification failures per email.
type RateLimiter struct {
	mu     sync.RWMutex
	store  map[string]*failEntry
}

var globalRL = &RateLimiter{store: make(map[string]*failEntry)}

func init() {
	go globalRL.cleanupLoop()
}

// ── Public API ──

// AllowSend returns true if the email can request another OTP send.
func (rl *RateLimiter) AllowSend(email string) bool {
	rl.mu.RLock()
	entry, ok := rl.store[email]
	rl.mu.RUnlock()

	if !ok {
		return true
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	// If blocked for fails, deny send too
	if now.Before(entry.BlockedUntil) {
		return false
	}

	// If send window expired, allow
	if now.After(entry.SendStart.Add(sendWindow)) {
		return true
	}

	return entry.SendCount < maxSendsPerWindow
}

// RecordSend increments the send counter for email.
func (rl *RateLimiter) RecordSend(email string) {
	rl.mu.RLock()
	entry, ok := rl.store[email]
	rl.mu.RUnlock()

	if !ok {
		entry = &failEntry{}
		rl.mu.Lock()
		rl.store[email] = entry
		rl.mu.Unlock()
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	if now.After(entry.SendStart.Add(sendWindow)) {
		entry.SendCount = 0
		entry.SendStart = now
	}

	entry.SendCount++
}

// RecordFail increments the fail counter for email.
// Returns true if this fail pushed the count over the threshold (now blocked).
func (rl *RateLimiter) RecordFail(email string) bool {
	rl.mu.RLock()
	entry, ok := rl.store[email]
	rl.mu.RUnlock()

	if !ok {
		entry = &failEntry{}
		rl.mu.Lock()
		rl.store[email] = entry
		rl.mu.Unlock()
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	// If currently blocked, just return true
	if now.Before(entry.BlockedUntil) {
		return true
	}

	// If window expired, reset
	if now.After(entry.WindowStart.Add(failWindow)) {
		entry.Count = 0
		entry.WindowStart = now
	}

	entry.Count++

	if entry.Count >= maxFailsBeforeBlock {
		entry.BlockedUntil = now.Add(blockDuration)
		return true
	}

	return false
}

// IsBlocked returns true if email is currently in a block period.
func (rl *RateLimiter) IsBlocked(email string) bool {
	rl.mu.RLock()
	entry, ok := rl.store[email]
	rl.mu.RUnlock()

	if !ok {
		return false
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	return time.Now().Before(entry.BlockedUntil)
}

// RemainingAttempts returns how many more attempts before block.
func (rl *RateLimiter) RemainingAttempts(email string) int {
	rl.mu.RLock()
	entry, ok := rl.store[email]
	rl.mu.RUnlock()

	if !ok {
		return maxFailsBeforeBlock
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	if now.Before(entry.BlockedUntil) {
		return 0
	}

	if now.After(entry.WindowStart.Add(failWindow)) {
		return maxFailsBeforeBlock
	}

	remaining := maxFailsBeforeBlock - entry.Count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Reset clears all fail records for email (on successful login).
func (rl *RateLimiter) Reset(email string) {
	rl.mu.Lock()
	delete(rl.store, email)
	rl.mu.Unlock()
}

// ── Background cleanup ──

// cleanupLoop is a background goroutine that periodically purges expired rate-limit entries.
func (rl *RateLimiter) cleanupLoop() {
	for range time.NewTicker(cleanupInterval).C {
		now := time.Now()
		rl.mu.Lock()
		for k, v := range rl.store {
			v.mu.Lock()
			expired := now.After(v.WindowStart.Add(failWindow)) && now.After(v.BlockedUntil)
			v.mu.Unlock()
			if expired {
				delete(rl.store, k)
			}
		}
		rl.mu.Unlock()
	}
}