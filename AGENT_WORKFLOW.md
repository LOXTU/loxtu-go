# Agent Workflow

## Before any task
1. Read `ARCHITECTURE.md`
2. Read the relevant feature's `README.md`
3. Read `DESIGN.md` for design tokens

## Adding a Feature
1. Create `internal/features/<name>/`
2. Implement handler, types, templates
3. Use `shared/templates.Base()` for full pages
4. Register in `cmd/server/main.go`
5. Add `README.md`

## Modifying UI
1. CSS: update the right module file (see `web/static/css/README.md`)
2. Use `var(--color-*)` — never hardcode
3. Dark/light: update `tokens.css` only
4. Both themes must use the same CSS variable structure

## HTMX
1. Endpoint returns HTML fragment, not full page
2. Check `HX-Request` header
3. Redirect: set `HX-Redirect` header
4. Load content: `hx-get` with `hx-trigger="load"`

## JSON Fallback
Every endpoint should support:
- `?format=json` query parameter
- `Accept: application/json` header
- Use `httputil.WantsJSON(r)` from shared package

## Theme
- Theme button is in `layout.templ` — don't duplicate
- JS events: `themeChanged` on `window`
- Clouds rebuild automatically on theme change

## Git Commits
- `feat(auth): ...`
- `fix(theme): ...`
- `style(dashboard): ...`
- `docs(auth): ...`
- `refactor(css): ...`