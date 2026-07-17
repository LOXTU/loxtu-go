# SessionAuthService

| Method | I/O |
|--------|-----|
| `Issue` / `IssueTokens` | pure JWT |
| `IssueSession` | Issue + `SessionStore.SaveRefreshToken` (port) |
| `Rotate` / `RevokeAllForEmail` | UserStore + SessionStore ports |

No SurrealDB/SQL. No deprecated aliases.
