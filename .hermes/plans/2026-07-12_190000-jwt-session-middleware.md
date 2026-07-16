# JWT Session & Middleware Implementation Plan

> **Goal:** Replace plain `loxtu_email` cookie with JWT access token + refresh token rotation, SurrealDB-backed sessions, middleware, and logout.

**Architecture:** JWT access token (15m) in HTTP-only cookie for stateless auth on protected routes. Refresh token (30d, SHA-256 hashed) stored in SurrealDB `sessions` table with rotation — each refresh issues a new pair. One session per employee — prior sessions deleted on new login. Middleware whitelists public routes, checks access JWT on everything else.

**Tech Stack:** `golang-jwt/jwt/v5` (already in go.sum), Chi middleware, SurrealDB sessions table, `crypto/sha256`.

---

### Task 1: Migration — sessions table

**Objective:** Define SurrealDB table for refresh token storage.

**Files:**
- Modify: `cmd/server/main.go` — append migration SQL
- Create: `internal/platform/db/migrations/002_sessions.surrealql`

**Step 1: Write migration SQL (002_sessions.surrealql)**

```surrealql
-- ==================================================================
-- 002_sessions.surrealql
-- Refresh token storage — one session per employee
-- ==================================================================

DEFINE TABLE sessions SCHEMAFULL;

-- email links to workers.email
DEFINE FIELD email      ON sessions TYPE string;
-- SHA-256 hash of the opaque refresh token
DEFINE FIELD token_hash ON sessions TYPE string;
-- ISO 8601 datetime
DEFINE FIELD expires_at ON sessions TYPE datetime;
-- ISO 8601 datetime
DEFINE FIELD created_at ON sessions TYPE datetime;

-- Fast lookup by email (delete-all prior sessions)
DEFINE INDEX idx_sessions_email ON sessions FIELDS email;

-- Fast lookup by token_hash (verification)
DEFINE INDEX idx_sessions_token ON sessions FIELDS token_hash;
```

**Step 2: Append to inline migration in `cmd/server/main.go`**

Add after the passkey_sessions block:

```go
// ── Sessions (refresh tokens) ──
DEFINE TABLE sessions SCHEMAFULL;
DEFINE FIELD email      ON sessions TYPE string;
DEFINE FIELD token_hash ON sessions TYPE string;
DEFINE FIELD expires_at ON sessions TYPE datetime;
DEFINE FIELD created_at ON sessions TYPE datetime;
DEFINE INDEX idx_sessions_email ON sessions FIELDS email;
DEFINE INDEX idx_sessions_token ON sessions FIELDS token_hash;
```

---

### Task 2: JWT helpers — `internal/features/auth/jwt.go`

**Objective:** Generate and validate access JWT with email + role payload.

**Files:**
- Create: `internal/features/auth/jwt.go`

```go
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims carries the full user identity for the JWT payload.
type AccessClaims struct {
	jwt.RegisteredClaims
	Email      string `json:"email"`
	TenantID   string `json:"tenant_id"`
	EmployeeID string `json:"employee_id"`
	Role       string `json:"role"`
}

// signingKey returns the HMAC secret from env (or a dev default).
func signingKey() []byte {
	key := os.Getenv("LOXTU_JWT_SECRET")
	if key == "" {
		key = "loxtu-dev-secret-do-not-use-in-prod"
	}
	return []byte(key)
}

// IssueAccessToken creates a short-lived JWT for the given user.
func IssueAccessToken(email, tenantID, employeeID, role string) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "loxtu",
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
		Email:      email,
		TenantID:   tenantID,
		EmployeeID: employeeID,
		Role:       role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey())
}

// ValidateAccessToken parses and validates an access JWT, returning claims.
func ValidateAccessToken(raw string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey(), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// IssueRefreshToken generates an opaque 32-byte refresh token.
// Returns the plain token (to give to client) and its SHA-256 hash (to store).
func IssueRefreshToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err := hmac.New(sha256.New, nil).Hash.Write(b); err != nil {
		return "", "", err
	}
	// Actually, use crypto/rand for randomness:
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(sum[:])
	return plain, hash, nil
}
```

**Dependencies:** `"crypto/rand"`, `"crypto/sha256"`, `"encoding/hex"`, `"github.com/golang-jwt/jwt/v5"` (already in go.sum).

---

### Task 3: Session store — `internal/features/auth/session.go`

**Objective:** CRUD for refresh tokens in SurrealDB (one session per email).

**Files:**
- Create: `internal/features/auth/session.go`

```go
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"

	"github.com/loxtu/loxtu-go/internal/platform/db"
)

// IssueTokens generates access + refresh tokens, persists refresh in DB,
// and revokes all prior sessions for this email (one-session-per-employee).
func IssueTokens(email, role string) (accessToken, refreshToken string, err error) {
	// 1. Generate access token
	accessToken, err = IssueAccessToken(email, role)
	if err != nil {
		return "", "", fmt.Errorf("access token: %w", err)
	}

	// 2. Generate refresh token + hash
	plain, hash, err := IssueRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("refresh token: %w", err)
	}

	// 3. Revoke all prior sessions for this email
	if db.Client != nil {
		if _, err := surrealdb.Query[any](context.Background(), db.Client,
			"DELETE sessions WHERE email = $email",
			map[string]any{"email": email},
		); err != nil {
			return "", "", fmt.Errorf("revoke prior sessions: %w", err)
		}

		// 4. Store new session
		if _, err := surrealdb.Query[any](context.Background(), db.Client,
			"CREATE sessions SET email = $email, token_hash = $hash, expires_at = <datetime>$expires, created_at = time::now()",
			map[string]any{
				"email":   email,
				"hash":    hash,
				"expires": time.Now().Add(30 * 24 * time.Hour).Unix(),
			},
		); err != nil {
			return "", "", fmt.Errorf("store session: %w", err)
		}
	}

	return accessToken, plain, nil
}

// RotateRefreshToken validates the current refresh token, deletes it,
// and issues a new pair. Returns new access + refresh tokens.
func RotateRefreshToken(oldPlain string) (accessToken, newPlain string, err error) {
	oldHash := sha256Hex(oldPlain)

	// 1. Find the session by token_hash
	results, err := surrealdb.Query[any](context.Background(), db.Client,
		"SELECT * FROM sessions WHERE token_hash = $hash",
		map[string]any{"hash": oldHash},
	)
	if err != nil {
		return "", "", fmt.Errorf("find session: %w", err)
	}
	rows, _ := (*results)[0].Result.([]any)
	if len(rows) == 0 {
		return "", "", fmt.Errorf("session not found or expired")
	}
	rm := rows[0].(map[string]any)
	email, _ := rm["email"].(string)

	// 2. Delete old session (rotation)
	surrealdb.Query[any](context.Background(), db.Client,
		"DELETE sessions WHERE token_hash = $hash",
		map[string]any{"hash": oldHash},
	)

	// 3. Issue new tokens (one-session-per-employee enforced inside)
	return IssueTokens(email, "")
}

// RevokeAllSessions deletes all refresh tokens for the given email.
func RevokeAllSessions(email string) error {
	if db.Client == nil {
		return nil
	}
	_, err := surrealdb.Query[any](context.Background(), db.Client,
		"DELETE sessions WHERE email = $email",
		map[string]any{"email": email},
	)
	return err
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
```

**Note:** Uses `surrealdb.Query[any]` directly (via `db.Client`) rather than the wrapper, to avoid import cycles.

---

### Task 4: Middleware — `internal/features/auth/middleware.go`

**Objective:** Chi middleware that reads access JWT from cookie, validates, injects email/role into context.

**Files:**
- Create: `internal/features/auth/middleware.go`

```go
package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type ctxKey string

const (
	CtxEmail      ctxKey = "email"
	CtxRole       ctxKey = "role"
	CtxTenantID   ctxKey = "tenant_id"
	CtxEmployeeID ctxKey = "employee_id"
)

// PublicPaths are routes that DO NOT require authentication.
var PublicPaths = []string{
	"/",
	"/health",
	"/auth/otp/send",
	"/auth/otp/verify",
	"/auth/passkey/login/begin",
	"/auth/passkey/login/finish",
	"/auth/passkey/begin",
	"/auth/passkey/finish",
	"/auth/passkey/skip",
	"/auth/passkey/register",
	"/auth/refresh",
	"/auth/logout",
	"/static/",
}

// Guard is a Chi middleware that validates access JWT from cookie.
// Routes in PublicPaths bypass the check.
// HTMX requests receive HX-Redirect header instead of redirect.
func Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Check if the path is public (allow prefix match for /static/ etc.)
		for _, p := range PublicPaths {
			if strings.HasPrefix(path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Read access token from cookie
		cookie, err := r.Cookie("loxtu_access")
		if err != nil {
			unauthorized(w, r)
			return
		}

		claims, err := ValidateAccessToken(cookie.Value)
		if err != nil {
			unauthorized(w, r)
			return
		}

		// Inject claims into context
		ctx := context.WithValue(r.Context(), CtxEmail, claims.Email)
		ctx = context.WithValue(ctx, CtxRole, claims.Role)
		ctx = context.WithValue(ctx, CtxTenantID, claims.TenantID)
		ctx = context.WithValue(ctx, CtxEmployeeID, claims.EmployeeID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GetEmail extracts the authenticated user's email from request context.
func GetEmail(r *http.Request) string {
	v, _ := r.Context().Value(CtxEmail).(string)
	return v
}

// GetRole extracts the authenticated user's role from request context.
func GetRole(r *http.Request) string {
	v, _ := r.Context().Value(CtxRole).(string)
	return v
}

// GetTenantID extracts the tenant ID from request context.
func GetTenantID(r *http.Request) string {
	v, _ := r.Context().Value(CtxTenantID).(string)
	return v
}

// GetEmployeeID extracts the employee ID from request context.
func GetEmployeeID(r *http.Request) string {
	v, _ := r.Context().Value(CtxEmployeeID).(string)
	return v
}
```

---

### Task 5: Wire tokens into login flow

**Objective:** After OTP verify and passkey finish — issue tokens and set cookies.

**Files:**
- Modify: `internal/features/auth/handler.go` — call `IssueTokens` on successful OTP verify
- Modify: `internal/features/passkey/handler.go` — call `IssueTokens` on passkey register/login finish

**Changes in auth/handler.go (handleVerifyOTP):**

```go
// After successful OTP verify, before redirect:
tokens, refreshPlain, err := IssueTokens(email, "worker")
if err != nil {
    log.Printf("ERROR IssueTokens: %v", err)
} else {
    http.SetCookie(w, &http.Cookie{
        Name: "loxtu_access", Value: tokens, Path: "/",
        MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode,
    })
    http.SetCookie(w, &http.Cookie{
        Name: "loxtu_refresh", Value: refreshPlain, Path: "/",
        MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode,
    })
}
// Also set short-lived loxtu_email for display purposes (non-sensitive)
http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: email, Path: "/", MaxAge: 3600})
```

**Changes in passkey/handler.go (handleFinishRegistration / handleFinishLogin):**

Same pattern: call `auth.IssueTokens(email, "worker")` → set `loxtu_access` + `loxtu_refresh` cookies before `HX-Redirect`.

**Note:** Import `github.com/loxtu/loxtu-go/internal/features/auth` in passkey handler to call `auth.IssueTokens`. To avoid circular imports, ensure `auth` package does NOT import `passkey` (it doesn't).

---

### Task 6: Refresh endpoint — `POST /auth/refresh`

**Objective:** Accept refresh token cookie, rotate it, return new access cookie.

**Files:**
- Modify: `internal/features/auth/handler.go` — add refresh handler + mount

```go
func handleRefresh(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("loxtu_refresh")
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    accessToken, newRefreshPlain, err := RotateRefreshToken(cookie.Value)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name: "loxtu_access", Value: accessToken, Path: "/",
        MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode,
    })
    http.SetCookie(w, &http.Cookie{
        Name: "loxtu_refresh", Value: newRefreshPlain, Path: "/",
        MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode,
    })
    w.WriteHeader(http.StatusNoContent)
}
```

Mount in `Mount()`:
```go
r.Post("/auth/refresh", handleRefresh)
```

---

### Task 7: Logout endpoint — `POST /auth/logout`

**Objective:** Delete all sessions for the user, clear cookies.

**Files:**
- Modify: `internal/features/auth/handler.go` — add logout handler + mount

```go
func handleLogout(w http.ResponseWriter, r *http.Request) {
    email := GetEmail(r)
    if email != "" {
        RevokeAllSessions(email)
    }
    http.SetCookie(w, &http.Cookie{Name: "loxtu_access", Value: "", Path: "/", MaxAge: -1})
    http.SetCookie(w, &http.Cookie{Name: "loxtu_refresh", Value: "", Path: "/", MaxAge: -1})
    http.SetCookie(w, &http.Cookie{Name: "loxtu_email", Value: "", Path: "/", MaxAge: -1})
    w.Header().Set("HX-Redirect", "/")
    w.WriteHeader(http.StatusOK)
}
```

Mount:
```go
r.Post("/auth/logout", handleLogout)
```

---

### Task 8: Apply middleware in main.go

**Objective:** Add `auth.Guard` middleware to protected routes.

**Files:**
- Modify: `cmd/server/main.go`

```go
// Protected routes — require valid JWT
r.Group(func(r chi.Router) {
    r.Use(auth.Guard)
    dashboard.Mount(r)   // /dashboard/*
    // Any future protected features mount here
})

// Public routes — no auth needed
auth.Mount(r)    // /, /auth/otp/*, /auth/refresh, /auth/logout
passkey.Mount(r) // /auth/passkey/*
```

**Note:** Move `dashboard.Mount(r)` inside the guarded group. `auth.Mount` stays outside. `passkey.Mount` stays outside (the begin/finish endpoints are public — they need to work before auth).

---

### Task 9: Clean up dashboard handler

**Objective:** Remove plain `loxtu_email` cookie reading, use `auth.GetEmail(r)` from context.

**Files:**
- Modify: `internal/features/dashboard/handler.go`

```go
// Before:
email := "user@airline.com"
if c, err := r.Cookie("loxtu_email"); err == nil && c.Value != "" {
    email = c.Value
}

// After:
email := auth.GetEmail(r)
if email == "" {
    email = "user@airline.com" // fallback
}
```

Add import: `"github.com/loxtu/loxtu-go/internal/features/auth"`

---

### Task 10: Verify & deploy

**Objective:** Build, test, deploy.

```bash
cd /opt/loxtu-go
go build ./...
templ generate
docker compose -f loxtu-go.yml build --no-cache loxtu-go
docker compose -f loxtu-go.yml up -d loxtu-go
docker logs loxtu-go --tail 10
```

Verify:
1. Registration: OTP → passkey → dashboard (check cookies set)
2. Login: passkey autofill → dashboard (check cookies set)
3. Refresh: call `/auth/refresh` with refresh cookie → get new access cookie
4. Logout: call `/auth/logout` → cookies cleared, redirect to `/`
5. Unauthenticated access to `/dashboard` → 401

---

### Migration note

The existing `passkey_sessions` table (WebAuthn challenges) stays in memory only. The new `sessions` table (refresh tokens) replaces the concept of a user session. These are different things — `passkey_sessions` = cryptographic ceremony state, `sessions` = authenticated session — keep them separate.
