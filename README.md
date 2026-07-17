# LOXTU

Ground handling SaaS for aviation ramp / ops — multi-tenant OTP + passkey auth, operational dashboard.

## Tech stack

| Layer | Choice |
|-------|--------|
| Language | Go 1.22+ (target 1.26) |
| HTTP | Chi v5 |
| DB | SurrealDB |
| UI | Templ + HTMX + Abyssal Aurora design system |
| Auth | OTP + WebAuthn (passkeys) + JWT |

## Quick start

```bash
cp .env.example .env   # set LOXTU_JWT_SECRET
make docker-up         # or: make run  (after Surreal/SMTP up)
```

Health: `GET /health` → `OK`

## Project structure

See [ARCHITECTURE.md](./ARCHITECTURE.md).

```
cmd/server/          Composition root (DI only)
internal/core/       Domain + ports
internal/adapters/   SurrealDB, SMTP, Telegram
internal/interfaces/ HTTP handlers, middleware, templ
internal/config/     ENV → Config structs
internal/shared/     PII helpers
migrations/          SurrealQL
web/                 //go:embed static
```

## Make targets

Run `make help` for the full list.

| Target | Action |
|--------|--------|
| `make build` | `go build ./cmd/server/` |
| `make run` | `go run ./cmd/server/` |
| `make test` / `make vet` | tests / static analysis |
| `make templ` | regenerate Templ |
| `make docker-up` / `docker-down` | stack via `loxtu-go.yml` |
| `make clean` | bin + `*_templ.go` |

## Design system

Reusable UI lives in `internal/interfaces/templates/shared/components/` — see that package README. All tokens in `web/static/css/tokens.css`.
