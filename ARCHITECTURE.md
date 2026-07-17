# LOXTU Architecture (Clean Architecture)

## Layers

```
cmd/server/main.go          Composition root (config → adapters → core → HTTP)
internal/core/              Business logic + ports (interfaces owned by client)
internal/adapters/          SurrealDB, SMTP, Telegram, rate limit implementations
internal/interfaces/        HTTP handlers, middleware, templ UI
internal/config/            ENV → Config structs (only place adapters' ENV is read)
internal/shared/            Cross-cutting helpers (MaskEmail, WriteJSON)
migrations/                 SurrealQL schema (control_plane + tenant_template)
web/                        //go:embed static assets
```

## Dependency rule

```
interfaces  →  core  ←  adapters
                 ↑
              config (composition root only)
```

- **Interfaces belong to the client** — ports live in `core/identity` / `core/audit`.
- Adapters implement those ports and return **domain types** (`*identity.User`, not infrastructure DTOs).
- Handlers are thin: parse HTTP → call core → render templ / set cookies / redirect.
- **No service locators**: no `var DB`, no `auth.EmailClient`. Wire only in `main` via constructors.
- Middleware uses `TenantResolver.ResolveByDomain` (Host / email-domain whitelist), never full email identity pre-auth.

## Core packages

| Package | Ports / services |
|---------|------------------|
| `core/identity` | User, Session, OTP, Passkey, OAuth, SessionAuthService, stores, RateLimiter, OTPSender, AlertSender |
| `core/audit` | SecurityEvent, Store, LogPublisher, Lifecycle |

## Rate limiting

Universal port: `core/identity/rate_limit.go`

```go
type RateLimiter interface {
    Allow(ctx, key, policy) (bool, error)
    Reset(ctx, key) error
    GetRemaining(ctx, key, policy) (int, error)
}

type RateLimitPolicy struct {
    MaxAttempts int
    Window      time.Duration // 0 = permanent quota (no time decay)
    Description string
}
```

| Policy | Max | Window | Use |
|--------|-----|--------|-----|
| `PolicyOTP` | 5 | 10m | OTP send / fail keys |
| `PolicyLogin` | 10 | 15m | general login thrash |
| `PolicyRegistration` | 30 | 1h | signup abuse |
| `PolicyMaxSessions` | 1 | **0** | one active session per user |

- **Window = 0**: permanent counter; only `Reset` clears it (no separate QuotaManager).
- Implementation: `adapters/ratelimit/memory.go` (`MemoryRateLimiter`). Future: Redis.
- Handlers call `rl.Allow(..., PolicyOTP)` with keys like `RateKeyOTPSend(email)`.

HTTP middleware sliding window (`interfaces/http/middleware/ratelimit.go`) remains for coarse IP/path flood control — not the domain policy port.

## Notification system

Family of channels in `core/identity/notifications.go` (not one mega-interface):

```go
type Notification struct {
    RecipientID string
    Metadata    map[string]string
}
type OTPNotification  struct { Notification; Code string; Expiry time.Duration }
type AlertNotification struct { Notification; Title, Body string; Data map[string]string }

type OTPSender interface   { SendOTP(ctx, OTPNotification) error }
type AlertSender interface { SendAlert(ctx, AlertNotification) error }
```

| Port | Purpose | Implementations |
|------|---------|-----------------|
| `OTPSender` | one-time codes | `adapters/messaging/smtp` (email); future SMS |
| `AlertSender` | push / cabin / on-screen | future Web Push, Telegram, cabin display |

`OTPService` depends on `OTPSender` only. SMTP maps `RecipientID` + `Code` into the email body.

## Adapters

| Package | Implements |
|---------|------------|
| `adapters/persistence/surrealdb` | User/Session/Cred/Audit/Tenant repos + Pool |
| `adapters/messaging/smtp` | `identity.OTPSender` |
| `adapters/ratelimit` | `identity.RateLimiter` (memory) |
| `adapters/security/telegram` | `audit.LogPublisher` (noop until enabled) |

## What was purged (M6+)

- `internal/features/*`, old `platform/*`, `infrastructure/email`
- Handler-local `OTPRateLimiter` → core `RateLimiter` + memory adapter
- `NotificationSender(to, code)` → `OTPSender(OTPNotification)`

Migrations live under `migrations/`.
