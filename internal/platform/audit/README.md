# Audit System — NIS2 / GDPR

## Tables

### `user_consents` (GDPR)

| Поле | Тип | Назначение |
|------|-----|-----------|
| `actor_id` | `option<record<users>>` | Кто дал согласие |
| `actor_email_masked` | `option<string>` | Маскированный email |
| `privacy_policy` | `string` | Версия политики, "v1" |
| `terms_of_service` | `string` | Версия TOS, "v1" |
| `consent_types` | `string` | "gdpr,nis2,soc2" |
| `client_ip` | `string` | IP |
| `reqid` | `string` | Request ID |
| `time_stamp` | `datetime` | DEFAULT `time::now()` |
| `expires_at` | `datetime` | DEFAULT `+2y` |

### `security_audit` (NIS2)

| Поле | Тип | Назначение |
|------|-----|-----------|
| `actor_id` | `option<record<users>>` | Кто совершил действие |
| `actor_email_masked` | `option<string>` | Маскированный email |
| `action` | `string` | `"auth.otp.verify"`, `"auth.logout"` |
| `status` | `string` | `"success"` / `"failure"` |
| `client_ip` | `string` | IP |
| `reqid` | `string` | Request ID |
| `time_stamp` | `datetime` | DEFAULT `time::now()` |
| `expires_at` | `datetime` | DEFAULT `+2y` |

## Tenant

Both tables are in the tenant namespace (not separate loxtu_audit). No `tenant_id` field.

## Functions

| Function | Table | Purpose |
|----------|-------|---------|
| `LogSecurityEvent` | `security_audit` | Auth events (login, logout, register) |
| `LogConsentEvent` | `user_consents` | Consent acceptance (GDPR) |
| `CheckConsent` | `user_consents` | Query latest consent by actor_id or email_masked |

## PII

- Full email NEVER stored in audit tables
- `actor_email_masked` = `mw.MaskEmail(email)` → `v***v@loxtu.com`