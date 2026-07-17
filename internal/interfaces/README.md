# internal/interfaces

## Rules

1. Thin HTTP: parse request → call **core** → render templ / redirect / JSON.
2. No SurrealDB / SMTP imports in handlers (use ports injected via constructors).
3. Middleware here is the migration target; legacy `platform/middleware` remains for features until M6.
4. Templates generate with `templ generate ./internal/interfaces/templates/...`.

## Layout

| Path | Content |
|------|---------|
| `http/handlers/` | AuthHandler, PasskeyHandler, DashboardHandler, Guard |
| `http/middleware/` | TenantRouter, CSRF, RateLimit, RequestID, SecurityHeaders |
| `templates/layouts/` | Base shell |
| `templates/auth/` | login, consent, passkey register |
| `templates/dashboard/` | shell / grid widgets |
