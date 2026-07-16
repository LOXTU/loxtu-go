# Shared UI Components

## Files

- `templates/layout.templ` — `Base(pageTitle, body)`: full HTML shell with head, aurora background, scripts, theme toggle, CSRF meta tag + JS config.
  Use `Base()` in every full-page template — it includes `<head>`, fonts, CSS, JS, passkey autofill, aurora background, theme button, and CSRF setup.
- `httputil/http.go` — `WantsJSON(r)` and `WriteJSON(w, status, v)` helpers shared across features.

## HTMX CSRF

The layout includes a `<meta>` tag and JS that reads `loxtu_csrf` cookie and sets `X-CSRF-Token` on every HTMX request:

```javascript
document.addEventListener('htmx:configRequest', function (e) {
    var csrf = ('; ' + document.cookie).split('; loxtu_csrf=').pop().split(';')[0];
    if (csrf) e.detail.headers['X-CSRF-Token'] = csrf;
});
```