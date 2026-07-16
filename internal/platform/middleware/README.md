# Middleware Architecture — `internal/platform/middleware/`

## API Path Structure (Multi-Tenant)

```
Global (control_plane NS)
├── GET  /favicon.ico
├── GET  /health
├── GET  /static/*                       (static files)
├── GET  /                               (login page — email input only)
├── POST /auth/otp/send                  (email → tenant router determines NS)

Tenant-Isolated (per-company NS, e.g. "loxtu", "ryanair", "public_travelers")
├── POST /auth/otp/verify                (verification within tenant NS)
├── GET  /auth/consent                   (consent page)
├── POST /auth/consent                   (accept consent)
├── POST /auth/passkey/begin             (passkey registration start)
├── POST /auth/passkey/finish            (passkey registration complete)
├── POST /auth/passkey/skip              (skip passkey)
├── GET  /auth/passkey/register          (passkey register page)
├── GET  /auth/passkey/login/begin       (passkey login start)
├── POST /auth/passkey/login/finish      (passkey login complete)
├── POST /auth/refresh                   (rotate JWT)
├── POST /auth/logout                    (revoke sessions)
├── GET  /dashboard/*                    (protected area)

Public Travelers (special NS "public_travelers")
├── All auth routes for users WITHOUT company email domain
├── No passkey (email-only auth)
└── No company workers record
```

## Middleware Stack (applied order)

```go
Recoverer → RealIP → TenantRouter → RequestID → SecurityHeaders → CSRF → RateLimit → Guard
```

### `TenantRouter` (tenant_router.go)

- Runs on every request
- If request has email (POST form or cookie) → parses domain with `net/mail`
- Looks up domain in control_plane's `tenant.domain_whitelist` array
- Resolves tenant code → writes to context as `ctx.Value(TenantCtxKey)`
- If domain not found → falls back to `"public_travelers"` NS
- If no email → writes empty string (global routes handle this)

### `DBContext` (db_context.go)

- Runs after TenantRouter
- Creates a **scoped SurrealDB session** via `db.Client.Attach(ctx)`
- Calls `scopedSession.Use(ctx, nsCode, dbName)` to switch to tenant NS
- Stores scoped session in request context
- Business-logic handlers use `db.ScopedQuery(ctx, sql, vars)` instead of `db.Query`
- Session is discarded after request completes (no connection leak)

### `RequestID`

- Generates unique ID per request, sets `X-Request-ID` header
- Logs structured `slog` line after response

### `Guard` (JWT)

- Applied per-route on `/dashboard/*`
- Reads tenant from context (set by TenantRouter)
- Injects tenant claims into context for downstream handlers

## Key Design Decisions

1. **Namespace-per-Tenant**: Each company (airline/airport) gets its own SurrealDB namespace. The `tenant` table in control_plane maps domain → NS code.

2. **Scoped Sessions**: Each HTTP request gets its own SurrealDB session via `db.Attach()`. This prevents race conditions when concurrent requests target different namespaces.

3. **Tenant Resolution**: Based on email domain → `tenant.domain_whitelist` lookup. If `user@loxtu.com` → NS `loxtu`. If `tourist@gmail.com` → NS `public_travelers`.

4. **OTP Send is Global**: Only `POST /auth/otp/send` runs in control_plane — it just stores the OTP in memory and sends email. No DB query needed. All subsequent routes run in the resolved tenant NS.

5. **Public Travelers**: Users without a company domain go to a shared `public_travelers` namespace. No passkey, no workers record — email-only auth with consent logging.

## Context Keys

```go
TenantCtxKey   // string — resolved tenant code ("loxtu", "public_travelers")
DBSessionCtxKey // *surrealdb.DB — scoped SurrealDB session for this request
```