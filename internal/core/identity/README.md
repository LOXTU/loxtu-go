# internal/core/identity

## Rules

1. Business rules for users, sessions, OTP, passkeys, OAuth — **no HTTP, no templ**.
2. Persistence only through `platform/persistence` ports (DTOs on the boundary).
3. Notifications only through `platform/messaging.NotificationSender`.
4. Allowed protocol libs: `golang-jwt/jwt`, `go-webauthn/webauthn` (protocol, not infra).
5. **Must NOT import**: chi, templ, `platform/db`, `infrastructure/email`, adapters, features.

## Files

| File | Role |
|------|------|
| `user.go` | `User`, `HasRole`, `HasSkill` |
| `session.go` | JWT issue/validate, `IssueTokens` → `TokenPair` (no DB) |
| `otp_service.go` | OTP gen/verify + rate limit + `NotificationSender` |
| `passkey_user.go` | `PasskeyUser` + handle encode/decode + `EmailHash` |
| `passkey_service.go` | WebAuthn ceremony orchestration via stores |
| `oauth_manager.go` | External identity → user + `IssueTokens` |
