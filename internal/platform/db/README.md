# SurrealDB Migration Layer — `internal/platform/db/`

## Architecture: Namespace-per-Tenant

```
┌─────────────────────────────────────────────────────┐
│  Control Plane (loxtu/loxtu)                        │
│  ┌───────────────────────────────────────────────┐  │
│  │  tenant                                       │  │
│  │  code, name, domain_whitelist, settings, ...  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Tenant Namespace (loxtu/loxtu)                     │
│  ┌──────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │  users   │ │ passkey_*    │ │  sessions    │    │
│  │  (was    │ │ (WebAuthn)   │ │ (JWT refresh)│    │
│  │  workers)│ │              │ │              │    │
│  └──────────┘ └──────────────┘ └──────────────┘    │
│  ┌──────────────────────┐ ┌──────────────────────┐  │
│  │  user_consents       │ │  security_audit      │  │
│  │  (GDPR: policy       │ │  (NIS2: auth logs,  │  │
│  │   versions, IP, ts)  │ │   errors, actions)  │  │
│  └──────────────────────┘ └──────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Migration Files

```
migrations/
├── control_plane/
│   └── 001_tenant.surrealql       # Tenant registry (code, domain_whitelist, settings)
│
└── tenant_template/
    ├── 001_users.surrealql         # Users (was workers) — no tenant_id
    ├── 002_passkey.surrealql       # passkey_users + passkey_credentials — record<users>
    ├── 003_sessions.surrealql      # JWT refresh sessions — record<users>
    └── 004_audit.surrealql         # user_consents (GDPR) + security_audit (NIS2)
```

## Schema Detail

### `tenant` (control_plane)

| Поле | Тип | Назначение |
|------|-----|-----------|
| `code` | `string` | Уникальный код тенанта (например "loxtu") |
| `name` | `string` | Отображаемое имя |
| `type` | `string` | Тип ("airport", "airline", etc.) |
| `domain_whitelist` | `array<string>` | Допустимые домены email |
| `settings` | `option<object>` | Настройки тенанта |
| `quotas` | `option<object>` | Квоты |
| `created_at` | `datetime` | DEFAULT `time::now()` |

### `users` (tenant_template, was workers)

| Поле | Тип | Изменение |
|------|-----|-----------|
| `email` | `string` | UNIQUE INDEX |
| `name` | `string` | — |
| `surname` | `string` | — |
| `role` | `string` | — |
| `skills` | `array<string>` | — |
| `is_active` | `bool` | — |
| ~~`tenant_id`~~ | 🔴 удалён | Больше не нужен (NS-per-Tenant) |
| ~~`uuid`~~ | 🔴 удалён | Избыточен (native id) |

### `passkey_users` / `passkey_credentials`

| Поле | Тип | Изменение |
|------|-----|-----------|
| `actor_id` | `record<users>` | **REQUIRED** (было `option<record<workers>>`) |
| ~~`tenant_id`~~ | 🔴 удалён | — |
| ~~`email`~~ | 🔴 удалён | — |

### `sessions`

| Поле | Тип | Изменение |
|------|-----|-----------|
| `actor_id` | `record<users>` | **REQUIRED** |
| `token_hash` | `string` | INDEX |
| ~~`tenant_id`~~ | 🔴 удалён | — |
| ~~`email`~~ | 🔴 удалён | — |

### `user_consents` (GDPR)

| Поле | Тип | Назначение |
|------|-----|-----------|
| `actor_id` | `record<users>` | Кто дал согласие |
| `actor_email_masked` | `option<string>` | Маскированный email |
| `privacy_policy` | `string` | Версия privacy policy |
| `terms_of_service` | `string` | Версия terms of service |
| `consent_types` | `string` | "gdpr,nis2,soc2" |
| `client_ip` | `string` | IP при согласии |
| `reqid` | `string` | Request ID |
| `expires_at` | `datetime` | DEFAULT `now() + 2y` |
| `time_stamp` | `datetime` | DEFAULT `time::now()` |

### `security_audit` (NIS2)

| Поле | Тип | Назначение |
|------|-----|-----------|
| `actor_id` | `record<users>` | Кто совершил действие |
| `actor_email_masked` | `option<string>` | Маскированный email |
| `action` | `string` | `"auth.otp.verify"`, `"auth.passkey.login"`, etc. |
| `resource_type` | `option<string>` | Тип ресурса |
| `resource_id` | `option<string>` | ID ресурса |
| `status` | `string` | `"success"` / `"failure"` |
| `client_ip` | `string` | IP клиента |
| `reqid` | `string` | Request ID |
| `time_stamp` | `datetime` | DEFAULT `time::now()` |
| `expires_at` | `datetime` | DEFAULT `now() + 2y` |

## Commands

### Run control_plane migration (one-time)

```bash
cat migrations/control_plane/001_tenant.surrealql | \
  docker exec -i surrealdb surreal sql -e http://localhost:8881 \
  --username root --password root \
  --namespace loxtu --database loxtu
```

### Run tenant_template migrations (per tenant namespace)

```bash
for f in migrations/tenant_template/*.surrealql; do
  cat $f | docker exec -i surrealdb surreal sql -e http://localhost:8881 \
    --username root --password root \
    --namespace loxtu --database loxtu
done
```

### Execute a query

```bash
echo "SELECT * FROM users;" | docker exec -i surrealdb surreal sql \
  -e http://localhost:8881 --username root --password root \
  --namespace loxtu --database loxtu
```

## Key Differences from v3.1.4

| Feature | Old | New |
|---------|-----|-----|
| Table name | `workers` | `users` |
| actor_id type | `option<record<workers>>` | `record<users>` (required) |
| tenant_id | Everywhere | 🔴 Removed (NS-per-Tenant) |
| Audit | Single `audit_event` | `user_consents` + `security_audit` |
| Tenant | 2 fields + settings | `code`, `domain_whitelist`, settings |
| Migration | Hardcoded in `main.go` | `.surrealql` files |