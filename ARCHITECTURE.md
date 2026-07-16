# LoxTu Go Architecture

## Stack
- Go 1.26, Chi v5.3, Templ v0.3, HTMX 2, SurrealDB 3
- CSS: "Abyssal Aurora" design system (glassmorphism 2.0)

## Directory Map
```
loxtu-go/
├── cmd/server/              # Entry point
├── internal/features/
│   ├── auth/                # Email/OTP authentication
│   ├── dashboard/           # Bento grid dashboard
│   └── shared/              # Shared layout, httputil helpers
└── web/static/
    ├── css/                 # Modular CSS (8 files, app.css as entry)
    ├── js/                  # aurora.js, theme.js, htmx.min.js
    └── icons/               # moon.svg, sun.svg
```

## Feature Pattern
```
features/<name>/
├── handler.go      # HTTP handlers (Chi routes)
├── types.go        # Domain types
├── templates/      # (optional) Templ sub-components
└── README.md
```

## Key Conventions
1. **CSS variables only in `tokens.css`** — `:root` for dark, `[data-theme="light"]` for light
2. **Full pages use `shared/templates.Base()`** — never write `<head>` manually
3. **HTMX fragments** — no `<html>`, no `<head>`, no scripts
4. **JSON fallback** — `?format=json` or `Accept: application/json` on every endpoint
5. **Theme toggle** — localStorage + `data-theme` attribute + `themeChanged` event
6. **Aurora clouds** — JS-managed, 5 clouds, rebuild on theme change
7. **No `background` shorthand** — use `background-color` for transitions
8. **No `transition: all`** — list specific properties