package surrealdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// TenantRepo looks up tenant codes from control_plane.tenant by domain.
type TenantRepo struct {
	pool      *Pool
	ControlNS string
	ControlDB string
}

// NewTenantRepo constructs a domain-based TenantResolver against control_plane NS.
func NewTenantRepo(pool *Pool) *TenantRepo {
	return &TenantRepo{pool: pool, ControlNS: "control_plane", ControlDB: "control_plane"}
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

// GetByTenantID loads a full Tenant by tenant_id from the control plane.
func (r *TenantRepo) GetByTenantID(ctx context.Context, tenantID string) (*identity.Tenant, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	ns, dbName := r.ControlNS, r.ControlDB
	if ns == "" {
		ns = "loxtu"
	}
	if dbName == "" {
		dbName = "loxtu"
	}
	res, err := r.pool.Query(ctx, ns, dbName,
		"SELECT * FROM tenant WHERE tenant_id = $tid LIMIT 1",
		map[string]any{"tid": tenantID},
	)
	if err != nil {
		return nil, fmt.Errorf("db query failed: %w", err)
	}
	rows := firstRows(res)
	if len(rows) == 0 {
		return nil, nil
	}
	rm, ok := rows[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected row type: %T", rows[0])
	}
	return mapTenantRow(rm), nil
}

// mapTenantRow maps a SurrealDB row → identity.Tenant.
func mapTenantRow(rm map[string]any) *identity.Tenant {
	t := &identity.Tenant{}
	t.TenantID, _ = rm["tenant_id"].(string)
	t.Name, _ = rm["name"].(string)
	t.Type, _ = rm["type"].(string)
	if wl, ok := rm["domain_whitelist"].([]any); ok {
		for _, d := range wl {
			if ds, ok := d.(string); ok {
				t.DomainWhitelist = append(t.DomainWhitelist, ds)
			}
		}
	}
	if ft, ok := rm["features"].([]any); ok {
		for _, f := range ft {
			if fs, ok := f.(string); ok {
				t.Features = append(t.Features, fs)
			}
		}
	}
	// SecurityPolicy
	if sp, ok := rm["security_policy"].(map[string]any); ok {
		if v, ok := sp["mfa_required"].(bool); ok {
			t.SecurityPolicy.MFARequired = v
		}
		if v, ok := sp["pin_enabled"].(bool); ok {
			t.SecurityPolicy.PinEnabled = v
		}
		if v, ok := sp["access_token_timeout_minutes"].(float64); ok {
			t.SecurityPolicy.AccessTokenTimeoutMinutes = int(v)
		}
		if v, ok := sp["refresh_token_timeout_minutes"].(float64); ok {
			t.SecurityPolicy.RefreshTokenTimeoutMinutes = int(v)
		}
	}
	// Quotas
	if q, ok := rm["quotas"].(map[string]any); ok {
		if v, ok := q["max_users"].(float64); ok {
			t.Quotas.MaxUsers = int(v)
		}
	}
	return t
}
