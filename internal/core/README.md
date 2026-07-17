# internal/core

## Rules

1. **Owns ports** used by this layer (client rule):
   - `identity.UserStore`, `SessionStore`, `CredentialStore`, `NotificationSender`
   - `audit.Store`, `LogPublisher`, `Lifecycle`
2. Adapters import **core**, never the reverse for infrastructure.
3. Zero chi / templ / Surreal / SMTP imports.

## Structure

| Package | Ports + logic |
|---------|----------------|
| `identity/` | users, JWT, OTP, passkey, OAuth |
| `audit/` | security events, severity filter |
