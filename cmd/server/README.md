# Server Entry Point

## Files
- `main.go` — Chi router setup, 2 SurrealDB connections (app + audit), middleware stack, feature mounting, email client init, WebAuthn RP init.

## Middleware Stack (order)
```
Recoverer → RealIP → RequestID → SecurityHeaders → CSRF → RateLimit → Heartbeat
```
Guard (JWT) is applied per-route on `/dashboard/*`.

## Startup sequence
1. SurrealDB connection (main DB: `loxtu/loxtu`)
2. Migration `001_passkey` (inline SQL: schema + tenant_id migration)
3. Email client (SMTP via Stalwart or DEV MODE)
4. Audit DB connection (separate NS/DB: `loxtu_audit/loxtu_audit`)
5. Audit migration (`audit_event` table SCHEMAFULL)
6. WebAuthn Relying Party init (RP ID, Origin)
7. Router setup & middleware
8. Feature mounting (auth public, passkey public, dashboard protected)
9. HTTP listener on LOXTU_HOST:LOXTU_PORT

## Config (.env)
| Var | Default | Description |
|-----|---------|-------------|
| `LOXTU_PORT` | 8880 | HTTP port |
| `LOXTU_HOST` | 0.0.0.0 | HTTP bind |
| `LOXTU_RPID` | app.loxtu.com | WebAuthn RP ID |
| `LOXTU_RPORIGIN` | https://app.loxtu.com | WebAuthn Origin |
| `LOXTU_JWT_SECRET` | — | HMAC signing key |
| `SURREALDB_ENDPOINT` | ws://surrealdb:8881/rpc | Main DB |
| `SURREALDB_AUDIT_NS` | loxtu_audit | Audit namespace |
| `SURREALDB_AUDIT_DB` | loxtu_audit | Audit database |
| `SMTP_ENABLED` | false | Toggle SMTP |
| `SMTP_HOST` | stalwart | SMTP server |
| `SMTP_PORT` | 465 | Implicit TLS port |

## Adding a Feature
1. Create `internal/features/<name>/`
2. Implement handler, types, templates
3. Use `shared/templates.Base()` for full pages
4. Register via `feature.Mount(r)` in main.go
5. Add README.md