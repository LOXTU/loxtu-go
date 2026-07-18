package surrealdb

import (
	"context"
	"testing"

	"github.com/loxtu/loxtu-go/internal/core/audit"
)

func TestAuditRepo_LogEvent_TenantMismatch(t *testing.T) {
	// No pool needed — tenant check happens before DB call
	repo := &AuditRepo{pool: nil}

	event := &audit.SecurityEvent{
		UserID:      "uuid-123",
		TenantID:    "aerlingus", // wrong tenant
		MaskedEmail: "v***y@loxtu.com",
		Action:      "auth.login",
		Status:      "success",
	}

	err := repo.LogEvent(context.Background(), event, "loxtu")
	if err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
	expected := "audit tenant mismatch: expected loxtu, got aerlingus"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestAuditRepo_LogEvent_EmptyTenantID(t *testing.T) {
	repo := &AuditRepo{pool: nil}

	event := &audit.SecurityEvent{
		UserID:   "uuid-123",
		TenantID: "", // empty
		Action:   "auth.login",
	}

	err := repo.LogEvent(context.Background(), event, "loxtu")
	if err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

func TestAuditRepo_LogEvent_NilPool(t *testing.T) {
	repo := &AuditRepo{pool: nil}

	event := &audit.SecurityEvent{
		UserID:      "uuid-123",
		TenantID:    "loxtu",
		MaskedEmail: "v***y@loxtu.com",
		Action:      "auth.login",
		Status:      "success",
	}

	err := repo.LogEvent(context.Background(), event, "")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
	if err.Error() != "db not connected" {
		t.Errorf("error = %q", err.Error())
	}
}

func TestAuditRepo_GetEvents_NilPool(t *testing.T) {
	repo := &AuditRepo{pool: nil}
	_, err := repo.GetEvents(context.Background(), "loxtu", "uuid-123", 10)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestAuditRepo_GetEvents_EmptyTenant(t *testing.T) {
	repo := &AuditRepo{pool: nil}
	_, err := repo.GetEvents(context.Background(), "", "uuid-123", 10)
	if err == nil {
		t.Fatal("expected error for empty tenant")
	}
}

func TestAuditRepo_LogSecurityEvent_NilPool(t *testing.T) {
	repo := &AuditRepo{pool: nil}
	err := repo.LogSecurityEvent(context.Background(), audit.SecurityEvent{Action: "test"})
	// Should not panic, but queue may work even without pool
	_ = err
}

func TestAuditRepo_Shutdown_Idempotent(t *testing.T) {
	repo := &AuditRepo{
		pool: nil,
		ch:   make(chan audit.SecurityEvent, 1),
	}
	repo.Start()
	repo.Shutdown()
	repo.Shutdown() // should not panic
}

func TestAuditRepo_MapAuditRow(t *testing.T) {
	rm := map[string]any{
		"user_id":       "uuid-123",
		"tenant_id":     "loxtu",
		"masked_email":  "v***y@loxtu.com",
		"action":        "auth.login",
		"resource_type": "session",
		"resource_id":   "sess-456",
		"status":        "success",
		"client_ip":     "1.2.3.4",
		"reqid":         "req-789",
	}
	ev := mapAuditRow(rm)
	if ev.UserID != "uuid-123" {
		t.Errorf("UserID = %q", ev.UserID)
	}
	if ev.TenantID != "loxtu" {
		t.Errorf("TenantID = %q", ev.TenantID)
	}
	if ev.MaskedEmail != "v***y@loxtu.com" {
		t.Errorf("MaskedEmail = %q", ev.MaskedEmail)
	}
	if ev.Action != "auth.login" {
		t.Errorf("Action = %q", ev.Action)
	}
	if ev.Status != "success" {
		t.Errorf("Status = %q", ev.Status)
	}
}

func TestAuditRepo_MapAuditRow_Empty(t *testing.T) {
	rm := map[string]any{}
	ev := mapAuditRow(rm)
	if ev.UserID != "" || ev.TenantID != "" {
		t.Error("empty row should produce empty event")
	}
}

func TestSecurityEvent_IsCritical(t *testing.T) {
	tests := []struct {
		action, status string
		want           bool
	}{
		{"auth.login.fail", "", true},
		{"auth.tenant_mismatch", "", true},
		{"session.revoke_all", "", true},
		{"passkey.fail", "", true},
		{"auth.login", "failure", true},
		{"auth.login", "denied", true},
		{"auth.login", "success", false},
		{"page.view", "success", false},
	}
	for _, tt := range tests {
		ev := audit.SecurityEvent{Action: tt.action, Status: tt.status}
		if got := ev.IsCritical(); got != tt.want {
			t.Errorf("IsCritical(%q, %q) = %v, want %v", tt.action, tt.status, got, tt.want)
		}
	}
}

func TestNewAuditRepo_NilPool(t *testing.T) {
	repo := NewAuditRepo(nil)
	if repo == nil {
		t.Fatal("should not be nil")
	}
	repo.Shutdown()
}
