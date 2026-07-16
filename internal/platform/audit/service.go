// Package audit provides audit logging to security_audit and user_consents tables.
package audit

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/loxtu/loxtu-go/internal/platform/db"
)

// AuditNS and AuditDB are the namespace/database where audit tables live.
const AuditNS = "loxtu"
const AuditDB = "loxtu"

// SecurityEvent is logged to the security_audit table (NIS2).
type SecurityEvent struct {
	ActorID          string `json:"actor_id"`
	ActorEmailMasked string `json:"actor_email_masked"`
	Action           string `json:"action"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	Status           string `json:"status"`
	ClientIP         string `json:"client_ip"`
	ReqID            string `json:"reqid"`
}

// ConsentEvent is logged to the user_consents table (GDPR).
type ConsentEvent struct {
	ActorID          string `json:"actor_id"`
	ActorEmailMasked string `json:"actor_email_masked"`
	PrivacyPolicy    string `json:"privacy_policy"`
	TermsOfService   string `json:"terms_of_service"`
	ConsentTypes     string `json:"consent_types"`
	ClientIP         string `json:"client_ip"`
	ReqID            string `json:"reqid"`
}

// ── Async Loggers ──────────────────────────────────────────────────────────

// LogSecurityEvent writes to security_audit asynchronously.
func LogSecurityEvent(ev SecurityEvent) {
	go writeSecurity(ev)
}

// LogConsentEvent writes to user_consents asynchronously.
func LogConsentEvent(ev ConsentEvent) {
	go writeConsent(ev)
}

func writeSecurity(ev SecurityEvent) {
	if db.DB == nil {
		log.Printf("[audit] DB not connected, dropping: %s %s", ev.Action, ev.Status)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()

	// Build query — only include actor_id if valid (never pass nil or malformed)
	vars := map[string]any{
		"action":             ev.Action,
		"status":             ev.Status,
		"client_ip":          ev.ClientIP,
		"reqid":              ev.ReqID,
		"actor_email_masked": ev.ActorEmailMasked,
		"time_stamp":         now.Format(time.RFC3339),
		"expires_at":         now.AddDate(2, 0, 0).Format(time.RFC3339),
		"resource_type":      ev.ResourceType,
		"resource_id":        ev.ResourceID,
	}
	q := "CREATE security_audit SET actor_email_masked = $actor_email_masked, action = $action, resource_type = $resource_type, resource_id = $resource_id, status = $status, client_ip = $client_ip, reqid = $reqid, time_stamp = <datetime>$time_stamp, expires_at = <datetime>$expires_at"
	if ev.ActorID != "" && !strings.Contains(ev.ActorID, "{") {
		if rec := db.GetRecordID(ev.ActorID); rec != nil {
			q = "CREATE security_audit SET actor_id = $actor_id, actor_email_masked = $actor_email_masked, action = $action, resource_type = $resource_type, resource_id = $resource_id, status = $status, client_ip = $client_ip, reqid = $reqid, time_stamp = <datetime>$time_stamp, expires_at = <datetime>$expires_at"
			vars["actor_id"] = rec
		}
	}

	_, err := db.DB.Query(ctx, AuditNS, AuditDB, q, vars)
	if err != nil {
		log.Printf("[audit] Write failed: %v (event: %s %s)", err, ev.Action, ev.Status)
	}
}

func writeConsent(ev ConsentEvent) {
	if db.DB == nil {
		log.Printf("[audit] DB not connected, dropping consent event")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()

	vars := map[string]any{
		"actor_email_masked": ev.ActorEmailMasked,
		"privacy_policy":     ev.PrivacyPolicy,
		"terms_of_service":   ev.TermsOfService,
		"consent_types":      ev.ConsentTypes,
		"client_ip":          ev.ClientIP,
		"reqid":              ev.ReqID,
		"time_stamp":         now.Format(time.RFC3339),
		"expires_at":         now.AddDate(2, 0, 0).Format(time.RFC3339),
	}
	q := "CREATE user_consents SET actor_email_masked = $actor_email_masked, privacy_policy = $privacy_policy, terms_of_service = $terms_of_service, consent_types = $consent_types, client_ip = $client_ip, reqid = $reqid, time_stamp = <datetime>$time_stamp, expires_at = <datetime>$expires_at"
	if ev.ActorID != "" && !strings.Contains(ev.ActorID, "{") {
		if rec := db.GetRecordID(ev.ActorID); rec != nil {
			q = "CREATE user_consents SET actor_id = $actor_id, actor_email_masked = $actor_email_masked, privacy_policy = $privacy_policy, terms_of_service = $terms_of_service, consent_types = $consent_types, client_ip = $client_ip, reqid = $reqid, time_stamp = <datetime>$time_stamp, expires_at = <datetime>$expires_at"
			vars["actor_id"] = rec
		}
	}

	_, err := db.DB.Query(ctx, AuditNS, AuditDB, q, vars)
	if err != nil {
		log.Printf("[audit] Consent write failed: %v", err)
	}
}

// ── Consent Check ──────────────────────────────────────────────────────────

type ConsentStatus int

const (
	ConsentUnknown  ConsentStatus = iota
	ConsentGranted
	ConsentRevoked
	ConsentExpired
)

// CheckConsent queries the latest consent for a user (by actor_id or email_masked).
func CheckConsent(actorID, emailMasked string) ConsentStatus {
	if db.DB == nil {
		return ConsentUnknown
	}

	if actorID != "" {
		s := queryConsentByField("actor_id", actorID)
		if s != ConsentUnknown {
			return s
		}
	}
	if emailMasked != "" {
		return queryConsentByField("actor_email_masked", emailMasked)
	}
	return ConsentUnknown
}

func queryConsentByField(field, value string) ConsentStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := db.DB.Query(ctx, AuditNS, AuditDB,
		"SELECT * FROM user_consents WHERE $field = $val ORDER BY time_stamp DESC LIMIT 1",
		map[string]any{"field": field, "val": value},
	)
	if err != nil || len(results) == 0 {
		return ConsentUnknown
	}

	rows, ok := results[0].Result.([]any)
	if !ok || len(rows) == 0 {
		return ConsentUnknown
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		return ConsentUnknown
	}

	// Check expires_at
	if exp, ok := row["expires_at"]; ok {
		var expiresAt time.Time
		switch e := exp.(type) {
		case string:
			expiresAt, _ = time.Parse(time.RFC3339, e)
		case time.Time:
			expiresAt = e
		}
		if !expiresAt.IsZero() && time.Now().After(expiresAt) {
			return ConsentExpired
		}
	}

	// Check consent_types (non-empty = granted)
	if ct, ok := row["consent_types"].(string); ok && ct != "" {
		return ConsentGranted
	}
	return ConsentUnknown
}

// RunMigration applies the audit schema migration using the pool.
func RunMigration() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrations := []string{
		// security_audit table
		"DEFINE TABLE security_audit SCHEMAFULL;",
		"DEFINE FIELD actor_id           ON security_audit TYPE option<record<users>>;",
		"DEFINE FIELD actor_email_masked ON security_audit TYPE option<string>;",
		"DEFINE FIELD action             ON security_audit TYPE string;",
		"DEFINE FIELD resource_type      ON security_audit TYPE option<string>;",
		"DEFINE FIELD resource_id         ON security_audit TYPE option<string>;",
		"DEFINE FIELD status             ON security_audit TYPE string;",
		"DEFINE FIELD client_ip          ON security_audit TYPE option<string>;",
		"DEFINE FIELD reqid              ON security_audit TYPE option<string>;",
		"DEFINE FIELD time_stamp         ON security_audIT TYPE datetime DEFAULT <datetime>time::now();",
		"DEFINE FIELD expires_at         ON security_audit TYPE datetime;",
		"DEFINE INDEX idx_audit_action ON security_audit FIELDS action;",
		"DEFINE INDEX idx_audit_actor  ON security_audit FIELDS actor_id;",
		"DEFINE INDEX idx_audit_ts     ON security_audit FIELDS time_stamp;",
		// user_consents table
		"DEFINE TABLE user_consents SCHEMAFULL;",
		"DEFINE FIELD actor_id           ON user_consents TYPE option<record<users>>;",
		"DEFINE FIELD actor_email_masked ON user_consents TYPE option<string>;",
		"DEFINE FIELD privacy_policy     ON user_consents TYPE string;",
		"DEFINE FIELD terms_of_service   ON user_consents TYPE string;",
		"DEFINE FIELD consent_types      ON user_consents TYPE string;",
		"DEFINE FIELD client_ip          ON user_consents TYPE option<string>;",
		"DEFINE FIELD reqid              ON user_consents TYPE option<string>;",
		"DEFINE FIELD time_stamp         ON user_consents TYPE datetime DEFAULT <datetime>time::now();",
		"DEFINE FIELD expires_at         ON user_consents TYPE datetime;",
		"DEFINE INDEX idx_consent_actor ON user_consents FIELDS actor_id;",
	}

	for _, stmt := range migrations {
		_, err := db.DB.Query(ctx, AuditNS, AuditDB, stmt, nil)
		if err != nil {
			if isAlreadyExists(err) {
				log.Printf("[audit] Migration statement skipped: %s", extractFieldName(stmt))
				continue
			}
			return fmt.Errorf("migration: %w", err)
		}
	}
	log.Printf("[audit] Migration completed")
	return nil
}

func isAlreadyExists(err error) bool {
	return err != nil && contains(err.Error(), "already exists")
}

func extractFieldName(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}