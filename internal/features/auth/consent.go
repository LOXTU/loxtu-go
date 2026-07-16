package auth

// ConsentShell is the consent page template fragment.
// It renders 3 checkboxes (GDPR, NIS2, SOC2) with "Accept" button disabled until all checked.

// ── Templ component helpers (rendered via handler) ──
// The actual template is in consent.templ, rendered by handleConsentPage().