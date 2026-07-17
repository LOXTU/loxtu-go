# internal/

| Dir | Role |
|-----|------|
| `core/` | Domain + ports (client-owned interfaces) |
| `adapters/` | External systems (SurrealDB, SMTP, Telegram) |
| `interfaces/` | HTTP + templ entry points |
| `config/` | ENV loading for composition root |
| `shared/` | PII-safe logging helpers |
| `platform/` | **deleted residual** — see ARCHITECTURE.md |

See `/ARCHITECTURE.md` for dependency rules.
