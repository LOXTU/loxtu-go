# Dashboard Feature

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/dashboard` | Guard (JWT) | Full page (via `Base()`) |
| GET | `/dashboard/grid` | Guard (JWT) | HTMX: grid fragment |
| GET | `/dashboard.json` | Guard (JWT) | JSON-LD for AI |
| GET | `/dashboard/panel/stats` | Guard (JWT) | HTMX: modal content |
| GET | `/dashboard/panel/close` | Guard (JWT) | HTMX: close modal |

All routes use `auth.Guard()` middleware directly (not via Chi Group/Route).

## PII

Email is read via `auth.GetEmail(r)` which extracts from JWT claims. Never logs full email in stdout.

## Files
- `handler.go` — HTTP handlers, JSON/HTML branching, exported `Handle*` functions
- `dashboard.templ` — DashboardShell, DashboardGrid, cards, DetailPanelContent
- `types.go` — CardData, DashboardData, GetData()