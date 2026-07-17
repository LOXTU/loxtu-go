// Package ratelimit implements identity.RateLimiter backends.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// MemoryRateLimiter is a process-local RateLimiter with mutex + map.
// Suitable for single-instance deploy; multi-instance should use Redis later.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*bucket
}

type bucket struct {
	count     int
	windowStart time.Time
}

// NewMemoryRateLimiter constructs a ready in-process limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{entries: make(map[string]*bucket)}
}

var _ identity.RateLimiter = (*MemoryRateLimiter)(nil)

// Allow consumes one attempt if under MaxAttempts within Window.
// Window = 0: permanent counter (never resets by time — only Reset).
func (r *MemoryRateLimiter) Allow(_ context.Context, key string, policy identity.RateLimitPolicy) (bool, error) {
	if key == "" || policy.MaxAttempts <= 0 {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.getOrCreate(key)
	r.rollWindow(b, policy)
	if b.count >= policy.MaxAttempts {
		return false, nil
	}
	b.count++
	return true, nil
}

// Reset removes all counters for key.
func (r *MemoryRateLimiter) Reset(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
	return nil
}

// GetRemaining returns MaxAttempts - count without consuming.
func (r *MemoryRateLimiter) GetRemaining(_ context.Context, key string, policy identity.RateLimitPolicy) (int, error) {
	if policy.MaxAttempts <= 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.entries[key]
	if !ok {
		return policy.MaxAttempts, nil
	}
	r.rollWindow(b, policy)
	rem := policy.MaxAttempts - b.count
	if rem < 0 {
		return 0, nil
	}
	return rem, nil
}

func (r *MemoryRateLimiter) getOrCreate(key string) *bucket {
	if b, ok := r.entries[key]; ok {
		return b
	}
	b := &bucket{windowStart: time.Now()}
	r.entries[key] = b
	return b
}

// rollWindow zeros the counter when the window expired (no-op for Window=0 permanent).
func (r *MemoryRateLimiter) rollWindow(b *bucket, p identity.RateLimitPolicy) {
	if p.Window <= 0 {
		return // permanent quota
	}
	if time.Since(b.windowStart) >= p.Window {
		b.count = 0
		b.windowStart = time.Now()
	}
}
