# internal/adapters/persistence/surrealdb

## Rules

1. Implements **core** ports only:
   - `identity.UserStore`, `SessionStore`, `CredentialStore`
   - `audit.Store` (+ `audit.Lifecycle`)
2. Public API returns **domain types** (`*identity.User`, `*Session`, `*PasskeyUser`).
3. Surreal helpers (`getRecordID`, `formatRecordID`) are **unexported**.
4. **No ENV** — `NewPool(ctx, Config)` receives config from `internal/config` / main.
5. **No package-level `var DB`**.
6. `NewAuditRepo` starts workers; call `Stop()` on shutdown.
