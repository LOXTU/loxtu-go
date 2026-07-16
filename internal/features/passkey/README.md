# Passkey Feature

## Schema

Tables `passkey_users` and `passkey_credentials` use `actor_id record<users>` (required, NOT optional).

## Tenant

Passkey tables are in the tenant namespace (resolved by `TenantRouter`). No `tenant_id` field.

## Audit

Passkey register/login events are logged to `security_audit` table.

## DB Queries

All queries use `actor_id` (record<users>) — no email field in the schema.
Lookup by email uses `db.LookupUserIDByEmail()` first, then queries by `actor_id`.