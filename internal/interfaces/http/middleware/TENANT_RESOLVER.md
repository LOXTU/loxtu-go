# TenantResolver

## Contract

```go
type TenantResolver interface {
    ResolveByDomain(ctx context.Context, domain string) (tenantCode string, err error)
}
```

**Domain**, not email identity: Host header (`app.loxtu.com`) or DNS part of form email (`air.ie`).

## Priority (TenantRouter)

1. JWT `tenant_ns` (authenticated)
2. HTTP `Host` → `ResolveByDomain(host)`
3. Form email **domain only** → `ResolveByDomain("air.ie")` → else `public`
4. `pre_auth_state` cookie NS
5. `public`

## Adapter

```go
repo := surrealdb.NewTenantRepo(pool) // SELECT code FROM tenant WHERE $domain IN domain_whitelist
mw.SetTenantResolver(repo)
// or: r.Use(mw.NewTenantRouter(repo))
```

No `platform/db` in middleware. Noop default → always public until wired.
