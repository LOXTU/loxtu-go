# internal/adapters/messaging/smtp

## Rules

1. Implements `identity.NotificationSender` (port owned by core).
2. Accepts pure `Config` — **no** `os.Getenv` / ConfigFromEnv in this package.
3. Composition root: `smtp.New(config.SMTPFromEnv())`.

## Files

| File | Role |
|------|------|
| `client.go` | SMTP client |
| `templates.go` | OTP HTML body |
