# CSS Structure

## Files
- `tokens.css` — all CSS custom properties. Dark: `:root`, light: `[data-theme="light"]`.
- `reset.css` — box-sizing reset.
- `base.css` — body, typography, utilities, scrollbar.
- `aurora.css` — background clouds and `.aurora-attract` glow.
- `components.css` — `.glass`, `.card-glass`, `.btn`, `.input-glass`, `.badge`.
- `animations.css` — `@keyframes` and HTMX transition classes.
- `dashboard.css` — bento grid, dashboard cards, theme toggle.
- `detail-panel.css` — slide-in panel from the right.
- `app.css` — imports all above.

## Rules
- Never hardcode colors; use `var(--color-*)`.
- Dark/light variants in `tokens.css` only.
- New reusable components → `components.css`.
- Page-specific styles → new file + import in `app.css`.