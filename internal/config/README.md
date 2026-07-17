# internal/config

## Rules

1. **Only place that reads `os.Getenv` for adapter wiring** (composition root helpers).
2. Adapters (`surrealdb`, `smtp`, …) accept pure `Config` structs — never call ENV.
3. `cmd/server/main.go` uses these helpers and injects configs into constructors.

## API

| Func | Returns |
|------|---------|
| `SurrealDBFromEnv()` | `surrealdb.Config` |
| `SMTPFromEnv()` | `smtp.Config` |
