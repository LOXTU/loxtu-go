package surrealdb

import (
	"context"
	"fmt"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// OAuthRepo implements identity.OAuthAccountStore.
type OAuthRepo struct {
	pool *Pool
}

// NewOAuthRepo constructs an OAuthAccountStore adapter.
func NewOAuthRepo(pool *Pool) *OAuthRepo {
	return &OAuthRepo{pool: pool}
}

var _ identity.OAuthAccountStore = (*OAuthRepo)(nil)

// LinkOrCreate finds existing link by provider+sub, or creates a new one.
// Returns the userID (existing or newly created).
func (r *OAuthRepo) LinkOrCreate(ctx context.Context, account *identity.OAuthAccount) (string, error) {
	if r.pool == nil {
		return "", fmt.Errorf("db not connected")
	}

	// Try to find existing link
	existing, err := r.FindByProvider(ctx, account.Provider, account.ProviderSub)
	if err == nil && existing != nil {
		return existing.UserID, nil
	}

	// Create new link
	if account.ID == "" {
		account.ID = fmt.Sprintf("oauth_%s_%s", account.Provider, account.ProviderSub)
	}
	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now()
	}

	_, err = r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`CREATE oauth_accounts SET id = $id, user_id = $uid, tenant_id = $tid, provider = $prov, provider_sub = $sub, created_at = <datetime>$ca`,
		map[string]any{
			"id":    account.ID,
			"uid":   account.UserID,
			"tid":   account.TenantID,
			"prov":  account.Provider,
			"sub":   account.ProviderSub,
			"ca":    account.CreatedAt.Format(time.RFC3339),
		},
	)
	if err != nil {
		return "", err
	}

	return account.UserID, nil
}

// FindByProvider finds an OAuth account by provider and provider_sub.
func (r *OAuthRepo) FindByProvider(ctx context.Context, provider, providerSub string) (*identity.OAuthAccount, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM oauth_accounts WHERE provider = $prov AND provider_sub = $sub LIMIT 1",
		map[string]any{"prov": provider, "sub": providerSub},
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
		return nil, nil
	}
	return mapOAuthRow(rm), nil
}

// FindByUserID finds all OAuth accounts for a user.
func (r *OAuthRepo) FindByUserID(ctx context.Context, userID string) ([]*identity.OAuthAccount, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM oauth_accounts WHERE user_id = $uid",
		map[string]any{"uid": userID},
	)
	if err != nil {
		return nil, err
	}
	rows := firstRows(results)
	var accounts []*identity.OAuthAccount
	for _, row := range rows {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		accounts = append(accounts, mapOAuthRow(rm))
	}
	return accounts, nil
}

// Unlink removes an OAuth account link.
func (r *OAuthRepo) Unlink(ctx context.Context, userID, provider string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE oauth_accounts WHERE user_id = $uid AND provider = $prov",
		map[string]any{"uid": userID, "prov": provider},
	)
	return err
}

func mapOAuthRow(rm map[string]any) *identity.OAuthAccount {
	a := &identity.OAuthAccount{}
	a.ID, _ = rm["id"].(string)
	a.UserID, _ = rm["user_id"].(string)
	a.TenantID, _ = rm["tenant_id"].(string)
	a.Provider, _ = rm["provider"].(string)
	a.ProviderSub, _ = rm["provider_sub"].(string)
	if ca, ok := parseTime(rm["created_at"]); ok {
		a.CreatedAt = ca
	}
	return a
}
