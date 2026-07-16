// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Rate Limit ────────────────────────────────────────────────────────────

// rateLimiter implements a sliding-window counter per key.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*slidingWindow
}

type slidingWindow struct {
	entries []time.Time
	limit   int
	window  time.Duration
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		windows: make(map[string]*slidingWindow),
	}
}

func (rl *rateLimiter) allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	sw, ok := rl.windows[key]
	if !ok {
		rl.windows[key] = &slidingWindow{
			entries: []time.Time{time.Now()},
			limit:   limit,
			window:  window,
		}
		return true, 0
	}

	now := time.Now()
	cutoff := now.Add(-window)

	// Prune old entries
	var valid []time.Time
	for _, t := range sw.entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	sw.entries = valid

	if len(valid) >= limit {
		// Retry-After = time until oldest entry expires
		retryAfter := sw.entries[0].Add(window).Sub(now)
		return false, retryAfter
	}

	sw.entries = append(sw.entries, now)
	return true, 0
}

// RateLimitRule defines a rate limit for a route pattern.
type RateLimitRule struct {
	Pattern string        // route prefix (e.g. /auth/otp/send)
	Limit   int           // max requests
	Window  time.Duration // time window
	KeyFunc func(r *http.Request) string // how to derive the key (IP, email, etc.)
	Methods []string      // HTTP methods to apply to (empty = all methods)
}

// RateLimit returns middleware that applies rate limiting per rule.
func RateLimit(rules []RateLimitRule) func(http.Handler) http.Handler {
	rl := newRateLimiter()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			for _, rule := range rules {
			if strings.HasPrefix(path, rule.Pattern) {
				// Check method filter — if Methods specified, only apply to matching methods
				if len(rule.Methods) > 0 {
					methodOk := false
					for _, m := range rule.Methods {
						if r.Method == m {
							methodOk = true
							break
						}
					}
					if !methodOk {
						continue
					}
				}
				key := rule.KeyFunc(r)
				allowed, retryAfter := rl.allow(key, rule.Limit, rule.Window)
				if !allowed {
						seconds := int(retryAfter.Seconds()) + 1
						w.Header().Set("Retry-After", itoa(seconds))
						log.Printf("[ratelimit] BLOCKED %s key=%s limit=%d/%s retry=%ds",
							path, key, rule.Limit, rule.Window.String(), seconds)
						http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
						return
					}
					break
				}
			}

			// General rate limit (per IP)
			allowed, retryAfter := rl.allow("ip:"+r.RemoteAddr, 100, time.Minute)
			if !allowed {
				seconds := int(retryAfter.Seconds()) + 1
				w.Header().Set("Retry-After", itoa(seconds))
				log.Printf("[ratelimit] GENERAL BLOCKED ip=%s retry=%ds", r.RemoteAddr, seconds)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ── Default rate limit rules ────────────────────────────────────────────

// DefaultRateLimitRules returns the standard set of rate limits.
func DefaultRateLimitRules() []RateLimitRule {
	return []RateLimitRule{
		{
			Pattern: "/auth/otp/send",
			Limit:   3,
			Window:  time.Hour,
			Methods: []string{"POST"},
			KeyFunc: func(r *http.Request) string { return "email:" + r.FormValue("email") },
		},
		{
			Pattern: "/auth/otp/verify",
			Limit:   5,
			Window:  5 * time.Minute,
			Methods: []string{"POST"},
			KeyFunc: func(r *http.Request) string { return "email:" + r.FormValue("email") },
		},
		{
			Pattern: "/auth/passkey/begin",
			Limit:   10,
			Window:  5 * time.Minute,
			Methods: []string{"POST"},
			KeyFunc: func(r *http.Request) string { return "ip:" + r.RemoteAddr },
		},
		{
			Pattern: "/auth/passkey/finish",
			Limit:   10,
			Window:  5 * time.Minute,
			Methods: []string{"POST"},
			KeyFunc: func(r *http.Request) string { return "ip:" + r.RemoteAddr },
		},
		{
			Pattern: "/auth/refresh",
			Limit:   10,
			Window:  5 * time.Minute,
			Methods: []string{"POST"},
			KeyFunc: func(r *http.Request) string { return "ip:" + r.RemoteAddr },
		},
	}
}
