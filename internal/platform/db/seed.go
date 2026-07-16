// Package db provides the SurrealDB client connection.
package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
)

// SeedDevelopmentData creates 3 tenants and applies tenant_template migrations to their NS.
// Called once at startup when the database is empty.
func SeedDevelopmentData() {
	log.Printf("[seed] Starting development data seeding...")

	tenants := []struct {
		Code           string
		DomainWhitelist []string
		Type           string
	}{
		{Code: "aerlingus", DomainWhitelist: []string{"aerlingus.com"}, Type: "airline"},
		{Code: "loxtu", DomainWhitelist: []string{"loxtu.com", "loxtu.test"}, Type: "airport"},
		{Code: "public", DomainWhitelist: []string{}, Type: "public"},
	}

	ctx := context.Background()

	for _, t := range tenants {
		// Create tenant record in control_plane (default NS)
		_, err := DB.Query(ctx, "loxtu", "loxtu",
			"UPSERT type::record('tenant', $code) SET code = $code, name = $name, type = $type, domain_whitelist = $whitelist, settings = {}, quotas = {}, created_at = time::now()",
			map[string]any{
				"code":      t.Code,
				"name":      t.Code + " default",
				"type":      t.Type,
				"whitelist": t.DomainWhitelist,
			},
		)
		if err != nil {
			log.Printf("[seed] WARNING: tenant %s create failed: %v", t.Code, err)
		} else {
			log.Printf("[seed] Tenant %s created (type=%s, whitelist=%v)", t.Code, t.Type, t.DomainWhitelist)
		}

		// Apply tenant_template migrations to the tenant's NS
		if err := applyTenantTemplate(ctx, t.Code); err != nil {
			log.Printf("[seed] WARNING: migration for NS=%s failed: %v", t.Code, err)
		} else {
			log.Printf("[seed] Migrations applied to NS=%s", t.Code)
		}
	}

	log.Printf("[seed] Development data seeding complete")
}

// applyTenantTemplate reads all .surrealql files from tenant_template/ and executes
// them in the target namespace using the pool. Batch — single query per file.
func applyTenantTemplate(ctx context.Context, ns string) error {
	cwd, _ := os.Getwd()
	dir := cwd + "/internal/platform/db/migrations/tenant_template/"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".surrealql") {
			continue
		}
		path := dir + entry.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		sql := strings.TrimSpace(string(data))
		if sql == "" {
			continue
		}

		// Execute entire file on the target NS — single round-trip
		_, err = DB.Query(ctx, ns, ns, sql, nil)
		if err != nil {
			// "already exists" is idempotent — skip
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			log.Printf("[seed]  WARNING: migration stmt failed in %s: %v", ns, err)
		}
	}
	return nil
}