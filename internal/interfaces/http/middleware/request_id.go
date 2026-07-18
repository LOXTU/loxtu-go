// Package middleware provides shared HTTP middleware components.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/loxtu/loxtu-go/internal/shared/httputil"
)

// ── Request ID ────────────────────────────────────────────────────────────

type ctxKey string

const RequestIDKey ctxKey = "request_id"

// logCtx is a mutable pointer stored in request context for sharing data
// between outer middleware (RequestID) and inner middleware (Guard).
type logCtx struct {
	Email     string
	TenantID  string
}

// logCtxKey is the context key for *logCtx.
var logCtxKey = &logCtx{}

func GetLogCtx(ctx context.Context) *logCtx {
	if lc, ok := ctx.Value(logCtxKey).(*logCtx); ok {
		return lc
	}
	return nil
}

// RequestID generates a unique ID for each request, injects it into context,
// sets the X-Request-ID response header, and logs a structured line via slog.
// Replaces Chi's middleware.Logger — emits one JSON-ish line per request.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Use existing X-Request-ID if proxied, otherwise generate
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = generateID()
		}

		// Create shared log context — Guard will write into it
		lc := &logCtx{}
		ctx := context.WithValue(r.Context(), logCtxKey, lc)
		ctx = context.WithValue(ctx, RequestIDKey, id)
		r = r.WithContext(ctx)

		// Add response header
		w.Header().Set("X-Request-ID", id)

		// Wrap the response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)

		// Build structured log entry
		durationMs := float64(time.Since(start).Microseconds()) / 1000.0
		status := lrw.statusCode
		path := r.URL.Path
		method := r.Method
		clientIP := extractClientIP(r)

		// Skip logging for static file requests (CSS/JS/images — noise)
		if strings.HasPrefix(path, "/static/") || path == "/favicon.ico" {
			return
		}

		// Read from shared log context (Guard may have filled it)
		email := lc.Email
		tenantID := lc.TenantID

		// Structured logging via slog
		slog.LogAttrs(context.Background(), slog.LevelInfo,
			"request",
			slog.String("reqid", id[:8]),
			slog.String("method", method),
			slog.String("path", path),
			slog.Int("status", status),
			slog.Float64("duration_ms", durationMs),
			slog.String("client_ip", clientIP),
			slog.String("tenant_id", tenantID),
			slog.String("email", email),
		)
	})
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	v, _ := ctx.Value(RequestIDKey).(string)
	return v
}

// ── Response Writer Wrapper ───────────────────────────────────────────────

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// ── Helpers ───────────────────────────────────────────────────────────────

// GetClientIP extracts the client IP from headers or RemoteAddr.
func GetClientIP(r *http.Request) string {
	return extractClientIP(r)
}

// extractClientIP returns the client IP from X-Forwarded-For, X-Real-IP, or RemoteAddr.
func extractClientIP(r *http.Request) string {
	// X-Forwarded-For: client, proxy1, proxy2
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// X-Real-IP
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return real
	}
	// Remove port from RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

func getCtxStr(ctx context.Context, key string) string {
	v, _ := ctx.Value(key).(string)
	return v
}

// MaskEmail masks an email for safe logging: v***v@loxtu.com
func MaskEmail(email string) string {
	return httputil.MaskEmail(email)
}

// ── ID Generator ──────────────────────────────────────────────────────────

// generateID creates a timestamp-prefixed random ID (similar to ULID).
func generateID() string {
	now := time.Now().UnixMilli()
	b := make([]byte, 12)
	rand.Read(b)
	ts := itohex(now, 8)
	id := hex.EncodeToString(b)
	return ts + id
}

func itohex(n int64, width int) string {
	const hexChars = "0123456789abcdef"
	if n == 0 {
		return pad("", width, '0')
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = hexChars[n&0xf]
		n >>= 4
	}
	s := string(buf[i:])
	return pad(s, width, '0')
}

func pad(s string, w int, c byte) string {
	if len(s) >= w {
		return s[:w]
	}
	b := make([]byte, w)
	for i := 0; i < w-len(s); i++ {
		b[i] = c
	}
	copy(b[w-len(s):], s)
	return string(b)
}
// SetLogEmail sets the masked email in the request's log context.
// Call from handlers when email is known (form value, cookie, JWT).
func SetLogEmail(r *http.Request, email string) {
	if lc := GetLogCtx(r.Context()); lc != nil && email != "" {
		lc.Email = MaskEmail(email)
	}
}
