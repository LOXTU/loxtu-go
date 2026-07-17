# internal/core/audit

## Rules

1. Pure domain types + filtering / severity logic only.
2. No SurrealDB writes here — persistence via `platform/persistence.AuditStore`.
3. No Telegram / HTTP — alerts via `platform/security.LogPublisher` (Milestone 3+).

## Files

| File       | Status (M1)      |
|------------|------------------|
| `event.go` | SecurityEvent, ConsentEvent stubs |
| `service.go` | Milestone 2 — filtering for admins |
