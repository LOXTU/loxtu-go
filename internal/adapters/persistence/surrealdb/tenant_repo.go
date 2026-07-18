package surrealdb

import (
	"context"
	"fmt"
	"strings"
)

// TenantRepo looks up tenant NS codes from control_plane (loxtu/loxtu.tenant)
// by **domain** (Host or email domain string). Implements middleware.TenantResolver.
type TenantRepo struct {
	pool      *Pool
	ControlNS string
	ControlDB string
}

// NewTenantRepo constructs a domain-based TenantResolver.
func NewTenantRepo(pool *Pool) *TenantRepo {
	return &TenantRepo{pool: pool, ControlNS: "loxtu", ControlDB: "loxtu"}
}

// ResolveByDomain maps domain → tenant.tenant_id via parameterized whitelist query.
// Returns "" if domain not whitelisted.
func (r *TenantRepo) ResolveByDomain(ctx context.Context, domain string) (string, error) {
	if r.pool == nil {
		return "", nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", nil
	}
	ns, dbName := r.ControlNS, r.ControlDB
	if ns == "" {
		ns = "loxtu"
	}
	if dbName == "" {
		dbName = "loxtu"
	}

	res, err := r.pool.Query(ctx, ns, dbName,
		"SELECT tenant_id FROM tenant WHERE $domain IN domain_whitelist LIMIT 1",
		map[string]any{"domain": domain},
	)
	if err != nil {
		return "", fmt.Errorf("db query failed: %w", err)
	}
	rows := firstRows(res)
	if len(rows) == 0 {
		return "", nil
	}
	rm, ok := rows[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected row type: %T", rows[0])
	}
	if tid, ok := rm["tenant_id"].(string); ok {
		return tid, nil
	}
	return "", nil
}
