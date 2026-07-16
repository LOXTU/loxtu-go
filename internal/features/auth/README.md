# Auth Feature

## Tenant Isolation

Auth runs in the tenant namespace resolved by `TenantRouter` middleware. The `OTP send` step is global (control_plane), all subsequent routes run in the tenant NS.

## Consent Flow

After OTP verify, `CheckConsent` queries `user_consents` table:
- Consent found & valid → issue tokens → `/dashboard`
- No consent → redirect to `/auth/consent`

Consent records are stored in `user_consents` with `privacy_policy` and `terms_of_service` versions.

## Audit

| Событие | Таблица |
|---------|---------|
| `auth.otp.verify` | `security_audit` |
| `auth.consent.granted` | `user_consents` |
| `auth.logout` | `security_audit` |

## PII

| Поле | stdout | audit |
|------|--------|-------|
| Email | `mw.MaskEmail()` → `v***v@loxtu.com` | `actor_email_masked` |
| Actor ID | `db.LookupUserIDByEmail()` | `record<users>` или NONE |