package surrealdb_test

import (
	"context"
	"testing"
	"time"

	"github.com/loxtu/loxtu-go/internal/adapters/persistence/surrealdb"
	"github.com/loxtu/loxtu-go/internal/config"
)

func TestTenantResolver_ResolveByDomain(t *testing.T) {
	// Connect to real SurrealDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.SurrealDBFromEnv()
	pool, err := surrealdb.NewPool(ctx, surrealdb.Config{
		Endpoint:  cfg.Endpoint,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Namespace: cfg.Namespace,
		Database:  cfg.Database,
		MaxConns:  cfg.MaxConns,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	repo := surrealdb.NewTenantRepo(pool)

	tests := []struct {
		domain   string
		expected string
	}{
		{"loxtu.com", "loxtu"},
		{"app.loxtu.com", ""},        // Host, not email domain — not in whitelist
		{"unknown.com", ""},          // not whitelisted
		{"", ""},                     // empty
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			code, err := repo.ResolveByDomain(context.Background(), tt.domain)
			if err != nil {
				t.Fatalf("ResolveByDomain(%q): %v", tt.domain, err)
			}
			if code != tt.expected {
				t.Errorf("ResolveByDomain(%q) = %q, want %q", tt.domain, code, tt.expected)
			}
		})
	}
}

func TestTenantResolver_ResolveByDomain_Aerlingus(t *testing.T) {
	// Seed aerlingus tenant first
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.SurrealDBFromEnv()
	pool, err := surrealdb.NewPool(ctx, surrealdb.Config{
		Endpoint:  cfg.Endpoint,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Namespace: cfg.Namespace,
		Database:  cfg.Database,
		MaxConns:  cfg.MaxConns,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	// Seed tenant:aerlingus with domain_whitelist
	_, err = pool.Query(ctx, cfg.Namespace, cfg.Database,
		`UPSERT tenant:aerlingus SET
			tenant_id = 'aerlingus',
			name = 'Aer Lingus',
			type = 'airline',
			domain_whitelist = ['aerlingus.com'],
			features = ['roster', 'turnaround'],
			security_policy = { mfa_required: false, pin_enabled: false, access_token_timeout_minutes: 15, refresh_token_timeout_minutes: 43200 },
			quotas = { max_users: 500 }`,
		nil,
	)
	if err != nil {
		t.Fatalf("seed aerlingus: %v", err)
	}

	repo := surrealdb.NewTenantRepo(pool)

	// Test email domain resolution
	code, err := repo.ResolveByDomain(context.Background(), "aerlingus.com")
	if err != nil {
		t.Fatalf("ResolveByDomain(aerlingus.com): %v", err)
	}
	if code != "aerlingus" {
		t.Errorf("ResolveByDomain(aerlingus.com) = %q, want %q", code, "aerlingus")
	}

	// Cleanup
	_, _ = pool.Query(ctx, cfg.Namespace, cfg.Database, "DELETE tenant:aerlingus", nil)
}
