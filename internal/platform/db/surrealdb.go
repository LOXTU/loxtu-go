// Package db provides the SurrealDB client connection.
package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/surrealdb/surrealdb.go"
)

// ── RecordID Helpers ──────────────────────────────────────────────────────

// FormatRecordID converts a SurrealDB record ID value to a clean "table:id" string.
// Handles:
//   - string: "users:xyz" → "users:xyz"
//   - fmt.Stringer: "users:xyz" → "users:xyz"
//   - map[string]any: {"tb":"users","id":"xyz"} → "users:xyz"
//   - Go struct repr: "{users xyz}" → "users:xyz"  (from SDK RecordID value type)
func FormatRecordID(id any) string {
	if id == nil {
		return ""
	}
	// Already a plain string
	if s, ok := id.(string); ok {
		return s
	}
	// fmt.Stringer interface (e.g. *models.RecordID pointer)
	if s, ok := id.(fmt.Stringer); ok {
		return s.String()
	}
	// Map with "tb"/"id" or "Table"/"ID" keys (some SDK versions)
	if m, ok := id.(map[string]any); ok {
		tb, _ := m["tb"].(string)
		if tb == "" {
			tb, _ = m["Table"].(string)
		}
		idVal := m["id"]
		if idVal == nil {
			idVal = m["ID"]
		}
		if tb != "" && idVal != nil {
			return fmt.Sprintf("%s:%v", tb, idVal)
		}
	}
	// Fallback: strip curly braces from Go struct representation "{users xyz}" → "users:xyz"
	s := fmt.Sprintf("%v", id)
	if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' {
		inner := s[1 : len(s)-1]
		// Find first space or comma to split table and id
		if idx := strings.IndexAny(inner, " ,"); idx > 0 {
			return inner[:idx] + ":" + strings.TrimSpace(inner[idx+1:])
		}
	}
	return s
}

// ── Email Hash ────────────────────────────────────────────────────────────

// EmailHash returns a SHA-256 hex digest of the email (lowercased).
func EmailHash(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(h[:])
}

// ── Backward-compatible helpers (all use Pool internally) ──────────────────

// Query executes a query on the default NS/DB (loxtu/loxtu).
func Query(sql string, vars map[string]any) ([]surrealdb.QueryResult[any], error) {
	if DB == nil {
		return nil, fmt.Errorf("db not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return DB.Query(ctx, "loxtu", "loxtu", sql, vars)
}

// QueryCtx executes a query on the specified NS/DB using the pool.
func QueryCtx(ctx context.Context, ns, dbName, sql string, vars map[string]any) ([]surrealdb.QueryResult[any], error) {
	if DB == nil {
		return nil, fmt.Errorf("db not connected")
	}
	return DB.Query(ctx, ns, dbName, sql, vars)
}

// ── LookupUserIDByEmailHash ───────────────────────────────────────────────

// LookupUserIDByEmailHash finds a user by email_hash, returns the record ID
// (e.g. "users:prl9dbtq2f36raesy0od") or empty string if not found.
func LookupUserIDByEmailHash(tenantNS, emailHash string) string {
	if DB == nil || emailHash == "" || tenantNS == "" {
		return ""
	}
	// ✅ ИСПРАВЛЕНО: используем QueryCtx с динамическим tenantNS
	results, err := QueryCtx(context.Background(), tenantNS, tenantNS, "SELECT id FROM users WHERE email_hash = $hash LIMIT 1", map[string]any{
		"hash": emailHash,
	})
	if err != nil || len(results) == 0 {
		return ""
	}

	switch r := results[0].Result.(type) {
	case map[string]any:
		return FormatRecordID(r["id"])
	case []any:
		if len(r) > 0 {
			if row, ok := r[0].(map[string]any); ok {
				return FormatRecordID(row["id"])
			}
		}
	}
	return ""
}

// LookupUserIDByEmail wraps LookupUserIDByEmailHash for backward compat.
func LookupUserIDByEmail(tenantNS, email string) string {
	return LookupUserIDByEmailHash(tenantNS, EmailHash(email))
}

// ── Migration ─────────────────────────────────────────────────────────────

// RunMigration executes a SurrealQL string as a migration step.
func RunMigration(name, sql string) error {
	log.Printf("[DB] Running migration: %s", name)

	stmts := strings.Split(sql, ";")
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		_, err := Query(stmt+";", nil)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				log.Printf("[DB]   (skipped — already exists)")
				continue
			}
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	log.Printf("[DB] Migration %s completed", name)
	return nil
}

// ── HasPasskeyCredentials ────────────────────────────────────────────────

// HasPasskeyCredentials checks if a user has any passkey credentials in the DB.
func HasPasskeyCredentials(tenantNS, email string) bool {
	if DB == nil || email == "" || tenantNS == "" {
		return false
	}
	actorID := LookupUserIDByEmailHash(tenantNS, EmailHash(email))
	if actorID == "" {
		return false
	}
	// ✅ ИСПРАВЛЕНО: используем QueryCtx с динамическим tenantNS
	res, err := QueryCtx(context.Background(), tenantNS, tenantNS, "SELECT count() FROM passkey_credentials WHERE actor_id = $actor GROUP ALL", map[string]any{"actor": GetRecordID(actorID)})
	if err != nil || len(res) == 0 {
		return false
	}
	if r, ok := res[0].Result.([]map[string]any); ok && len(r) > 0 {
		if c, ok := r[0]["count"].(float64); ok && c > 0 {
			return true
		}
	}
	return false
}

// ── LoadMigrationFile ─────────────────────────────────────────────────────

// LoadMigrationFile reads a .surrealql migration file and returns its content.
func LoadMigrationFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[DB] WARNING: cannot read migration %s: %v", path, err)
		return ""
	}
	return string(data)
}