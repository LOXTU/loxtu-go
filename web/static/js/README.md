# JavaScript

## Files
- `htmx.min.js` — HTMX 2.x.
- `passkey.js` — WebAuthn passkey registration and login. Conditional mediation with AbortController. Delegated click handlers for `.js-register-passkey`, `.js-skip-passkey`, `.js-signin-passkey`.
- `otp.js` — OTP input auto-focus, paste support, auto-submit on 6 digits.
- `aurora.js` — animated clouds with cursor attraction. Lerp-based. Listens to `themeChanged` for cloud rebuild.
- `theme.js` — dark/light toggle. Exposes `loxtuTheme.toggle()`, dispatches `themeChanged`.

## Conventions
- Vanilla JS, no frameworks.
- IIFE modules, no global scope pollution (except `loxtuTheme`).
- Listen to HTMX events: `htmx:configRequest` (CSRF token), `htmx:beforeSwap`, `htmx:afterSwap`.
- CSRF token read from `loxtu_csrf` cookie and injected via `htmx:configRequest`.