# LOXTU Architecture v2.0 — Hard Rules

> These rules are MANDATORY for all code, AI agents, and contributors.
> Violating them breaks GDPR/NIS2 compliance, multi-tenant isolation, or build stability.

---

## 1. Identifiers

| Rule | Correct | Forbidden |
|------|---------|-----------|
| User identifier | `user_id` (UUID v7, generated in Go) | `id`, `actor_id`, `subject_id`, `users:abc123` |
| Tenant identifier | `tenant_id` (string) | `tenant_code`, `tenant_ns`, `ns_name` |
| Session identifier | `token_hash` (SHA-256 of refresh token) | Storing raw tokens |

**Enforcement:** Every `SELECT`, `CREATE`, `UPDATE` in Go must use `user_id` and `tenant_id`. JWT claims: `{"user_id": "...", "tenant_id": "..."}`.

---

## 2. PII — Envelope Encryption

| Layer | Where | Format |
|-------|-------|--------|
| KEK (Key Encryption Key) | `LOXTU_DATA_KEY` env var | Base64-encoded 32-byte AES-256 key |
| DEK (Data Encryption Key) | `users.encrypted_dek` | AES-256-GCM encrypted by KEK |
| PII (email, name, phone, DOB) | `users.*_ciphertext` | AES-256-GCM encrypted by DEK |

**Rules:**
- Plain-text email/name/phone/DOB **NEVER** written to DB
- Lookup by `email_hash` = `SHA-256(lowercase(email) + pepper)`
- Display via `masked_email` = `"v***y@loxtu.com"` (not PII)
- `LOXTU_HASH_PEPPER` — never rotate without full data migration

**Crypto-shredding (GDPR Art. 17):**
```sql
UPDATE users SET
    encrypted_dek = NONE,
    email_hash = rand::string(32),
    email_ciphertext = NONE,
    name_ciphertext = NONE,
    -- ... all *_ciphertext = NONE
    status = 'erased'
WHERE user_id = $id
```
Destroying DEK makes all ciphertext permanently unreadable (including backups).

---

## 3. Tenant Isolation

| Concern | Rule |
|---------|------|
| User data | `tenant_id` field in `users`, `passkey_users`, `sessions` |
| Audit data | Separate namespace: `NS=audit, DB=<tenant_id>` |
| Tenant resolution | By email domain: `WHERE $domain IN domain_whitelist` |
| Cross-tenant check | Guard: `claims.TenantID != routerTenant` → 403 Forbidden |

**Forbidden:** Querying `NS=<tenant>` for audit data. Audit is ALWAYS `NS=audit`.

---

## 4. Authentication — Separate Tables

| Method | Table | Fields |
|--------|-------|--------|
| Passkey (WebAuthn) | `passkey_users` + `passkey_credentials` | `user_id`, `handle`, `kid`, `public_key` |
| PIN | `user_pins` | `user_id`, `pin_hash` (Argon2id) |
| OAuth/SSO | `oauth_accounts` | `user_id`, `provider`, `provider_sub` |
| Devices | `user_devices` | `user_id`, `device_id`, `vapid_endpoint` |

**Rule:** `users` table contains ONLY identity + PII + RBAC. Authentication methods are in separate tables. If a new method appears (biometrics, FIDO2.1), create a new table — never add to `users`.

---

## 5. JWT Claims

```json
{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "tenant_id": "loxtu",
    "role": "worker",
    "permissions": ["flights.read"],
    "iss": "loxtu",
    "sub": "550e8400-e29b-41d4-a716-446655440000",
    "exp": 1234567890,
    "iat": 1234567800
}
```

**Forbidden fields:** `email`, `actor_id`, `tenant_ns`, `subject` (as email).

**Token timeout:** Read from `tenant.security_policy.access_token_timeout_minutes`, not hardcoded.

---

## 6. Clean Architecture Layers

```
cmd/server/main.go          ← Composition Root (DI only)
internal/config/            ← ENV → Config structs (no adapter imports)
internal/security/          ← Crypto primitives (AES, Argon2, KeyManager)
internal/core/identity/     ← Domain entities + ports (interfaces)
internal/core/audit/        ← Audit domain
internal/adapters/          ← SurrealDB, SMTP, Telegram (implement core ports)
internal/interfaces/http/   ← Handlers, middleware, templates
```

**Import rules:**
- `core` NEVER imports `adapters`, `interfaces`, or `external`
- `adapters` imports `core` (implements ports) + `security`
- `interfaces` imports `core` + `adapters` (constructor DI)
- `config` NEVER imports `adapters` (define structs locally)

---

## 7. Audit

| Rule | Detail |
|------|--------|
| Namespace | `NS=audit, DB=<tenant_id>` |
| Fields | `user_id`, `tenant_id`, `masked_email`, `action`, `status` |
| Tenant guard | `LogEvent` checks `event.TenantID == expectedTenantID` |
| Retention | `expires_at = time::now() + 2y` (NIS2 minimum) |
| Worker pool | Async via buffered channel, 5 workers |

**Forbidden:** Writing audit to `NS=<tenant>`. Audit is ALWAYS isolated.

---

## 8. SurrealDB Schema Rules

| Rule | Detail |
|------|--------|
| Schema | `SCHEMAFULL` for all tables |
| Nullable fields | `TYPE option<T>` (not `TYPE none \| T`) |
| Timestamps | `created_at`, `updated_at` on every table |
| Indexes | Unique on `user_id`, `email_hash`, `token_hash`, `kid` |
| No record IDs in Go | Use `user_id` (UUID string), not `users:abc123` |

---

## 9. Testing

| Level | Where | What |
|-------|-------|------|
| Unit | `*_test.go` in package | Domain logic, crypto, JWT |
| Integration | `adapters/persistence/surrealdb/*_test.go` | Real SurrealDB (Docker) |
| E2E | `tests/e2e/` | Full HTTP flow with httptest |

**Rule:** `go test ./...` must PASS before any commit. Tests run inside Docker with real SurrealDB.

---

## 10. Migration Files

| Rule | Detail |
|------|--------|
| Location | `migrations/control_plane/`, `migrations/tenant_template/`, `migrations/audit_template/` |
| Never DELETE | Only ADD new fields/tables |
| Sync with DB | Migration files MUST match actual DB schema |
| Apply order | `001` → `002` → `003` → ... (sequential) |

**Current tables:**
- `control_plane/001_tenant.surrealql` → `tenant` (with seeds)
- `tenant_template/001_users.surrealql` → `users`
- `tenant_template/002_passkey.surrealql` → `passkey_users`, `passkey_credentials`
- `tenant_template/003_sessions.surrealql` → `sessions`
- `tenant_template/004_oauth_accounts.surrealql` → `oauth_accounts`
- `tenant_template/005_user_pins.surrealql` → `user_pins`
- `tenant_template/006_user_devices.surrealql` → `user_devices`
- `audit_template/001_audit.surrealql` → `user_consents`, `security_audit`

---

## 11. Deployment

| Component | Port | Network |
|-----------|------|---------|
| loxtu-go | 8880 | loxtu-net |
| surrealdb | 8881 | loxtu-net |
| caddy | 80/443 | loxtu-net |

**Docker compose:** `docker compose -f loxtu-go.yml down && build --no-cache && up -d`

**Environment:** All secrets in `.env`, never in code. See `.env.example` for required keys.
