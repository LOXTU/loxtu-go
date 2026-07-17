package surrealdb

import (
	"context"
	"fmt"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// UserRepo implements identity.UserStore — returns domain *identity.User only.
type UserRepo struct {
	pool *Pool
}

// NewUserRepo constructs a UserStore adapter.
func NewUserRepo(pool *Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

var _ identity.UserStore = (*UserRepo)(nil)

// FindByActorID loads a user by full record id in ns.
func (r *UserRepo) FindByActorID(ctx context.Context, ns, actorID string) (*identity.User, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	rec := getRecordID(actorID)
	if rec == nil {
		return nil, fmt.Errorf("invalid actor id: %s", actorID)
	}
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT * FROM users WHERE id = $id LIMIT 1",
		map[string]any{"id": rec},
	)
	if err != nil {
		return nil, err
	}
	rows := firstRows(results)
	if len(rows) == 0 {
		return nil, nil
	}
	rm, ok := rows[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected user row type %T", rows[0])
	}
	return mapUserRow(rm, ns), nil
}

// FindByEmailHash finds a user by SHA-256 email hash in ns.
func (r *UserRepo) FindByEmailHash(ctx context.Context, ns, emailHash string) (*identity.User, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	if emailHash == "" || ns == "" {
		return nil, nil
	}
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT * FROM users WHERE email_hash = $hash LIMIT 1",
		map[string]any{"hash": emailHash},
	)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	switch res := results[0].Result.(type) {
	case map[string]any:
		return mapUserRow(res, ns), nil
	case []any:
		if len(res) == 0 {
			return nil, nil
		}
		rm, ok := res[0].(map[string]any)
		if !ok {
			return nil, nil
		}
		return mapUserRow(rm, ns), nil
	default:
		return nil, nil
	}
}

// CreateMinimalUser inserts progressive-profiling row; returns actorID.
func (r *UserRepo) CreateMinimalUser(ctx context.Context, ns, emailHash string) (string, error) {
	if r.pool == nil {
		return "", fmt.Errorf("db not connected")
	}
	if existing, err := r.FindByEmailHash(ctx, ns, emailHash); err == nil && existing != nil {
		return existing.ActorID, nil
	}

	results, err := r.pool.Query(ctx, ns, ns,
		"CREATE users SET email_hash = $hash, tenant_id = $tenant, is_active = false RETURN id",
		map[string]any{
			"hash":   emailHash,
			"tenant": ns,
		},
	)
	if err != nil {
		if existing, lerr := r.FindByEmailHash(ctx, ns, emailHash); lerr == nil && existing != nil {
			return existing.ActorID, nil
		}
		return "", fmt.Errorf("create user: %w", err)
	}
	if len(results) > 0 {
		if rows, ok := results[0].Result.([]any); ok && len(rows) > 0 {
			if row, ok := rows[0].(map[string]any); ok {
				if id, ok := row["id"]; ok {
					return formatRecordID(id), nil
				}
			}
		}
		if row, ok := results[0].Result.(map[string]any); ok {
			if id, ok := row["id"]; ok {
				return formatRecordID(id), nil
			}
		}
	}
	if existing, err := r.FindByEmailHash(ctx, ns, emailHash); err == nil && existing != nil {
		return existing.ActorID, nil
	}
	return "", fmt.Errorf("create user: empty actor id after create")
}

// mapUserRow maps raw Surreal row → domain User (mapping lives in adapter only).
func mapUserRow(rm map[string]any, ns string) *identity.User {
	u := &identity.User{
		ActorID:  formatRecordID(rm["id"]),
		TenantNS: ns,
	}
	if h, ok := rm["email_hash"].(string); ok {
		u.EmailHash = h
	}
	if e, ok := rm["email"].(string); ok {
		u.Email = e
	}
	if role, ok := rm["role"].(string); ok {
		u.Role = role
	}
	if emp, ok := rm["employee_id"].(string); ok {
		u.EmployeeID = emp
	}
	if active, ok := rm["is_active"].(bool); ok {
		u.IsActive = active
	}
	if tenant, ok := rm["tenant_id"].(string); ok && tenant != "" {
		u.TenantNS = tenant
	}
	return u
}
