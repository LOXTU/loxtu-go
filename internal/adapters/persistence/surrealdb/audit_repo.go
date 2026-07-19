package surrealdb

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/audit"
)

const (
	auditQueueSize   = 1024
	auditWorkerCount = 5
)

// AuditRepo implements audit.Store with an async worker pool.
// Audit records are written to NS=audit, DB=<tenant_id> for isolation.
type AuditRepo struct {
	pool *Pool

	ch     chan audit.SecurityEvent
	wg     sync.WaitGroup
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

// NewAuditRepo constructs AuditStore and starts the worker pool.
func NewAuditRepo(pool *Pool) *AuditRepo {
	r := &AuditRepo{
		pool: pool,
		ch:   make(chan audit.SecurityEvent, auditQueueSize),
	}
	r.Start()
	return r
}

var (
	_ audit.Store     = (*AuditRepo)(nil)
	_ audit.Lifecycle = (*AuditRepo)(nil)
)

// Start launches the audit worker pool (idempotent). Called from NewAuditRepo.
func (r *AuditRepo) Start() {
	r.once.Do(func() {
		for i := 0; i < auditWorkerCount; i++ {
			r.wg.Add(1)
			go r.worker()
		}
		log.Printf("[audit] Worker pool started: %d workers, queue=%d", auditWorkerCount, auditQueueSize)
	})
}

// Stop / Shutdown drains workers.
func (r *AuditRepo) Stop() { r.Shutdown() }

// Shutdown closes the queue and waits for workers.
func (r *AuditRepo) Shutdown() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.ch)
	r.mu.Unlock()
	r.wg.Wait()
	log.Printf("[audit] Worker pool shut down")
}

// LogSecurityEvent queues a security event (non-blocking; drops if full).
func (r *AuditRepo) LogSecurityEvent(ctx context.Context, event audit.SecurityEvent) error {
	select {
	case r.ch <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		log.Printf("[audit] Queue full, dropping security event: %s %s", event.Action, event.Status)
		return fmt.Errorf("audit queue full")
	}
}

func (r *AuditRepo) worker() {
	defer r.wg.Done()
	for ev := range r.ch {
		r.writeSecurity(ev)
	}
}

func (r *AuditRepo) writeSecurity(ev audit.SecurityEvent) {
	if r.pool == nil {
		log.Printf("[audit] DB not connected, dropping: %s %s", ev.Action, ev.Status)
		return
	}

	// Resolve tenant_id — prefer v2 field, fallback to legacy
	tenantID := ev.TenantID
	if tenantID == "" {
		tenantID = "public" // fallback
	}

	// Resolve user_id — prefer v2 field
	userID := ev.UserID

	// Resolve masked_email — prefer v2 field
	maskedEmail := ev.MaskedEmail

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	vars := map[string]any{
		"user_id":       userID,
		"tenant_id":     tenantID,
		"masked_email":  maskedEmail,
		"action":        ev.Action,
		"resource_type": ev.ResourceType,
		"resource_id":   ev.ResourceID,
		"status":        ev.Status,
		"client_ip":     ev.ClientIP,
		"reqid":         ev.ReqID,
		"time_stamp":    now.Format(time.RFC3339),
		"expires_at":    now.AddDate(2, 0, 0).Format(time.RFC3339),
	}

	// Write to separate audit namespace per tenant
	_, err := r.pool.Query(ctx, "audit", tenantID,
		`CREATE security_audit SET
			user_id = $user_id,
			tenant_id = $tenant_id,
			masked_email = $masked_email,
			action = $action,
			resource_type = $resource_type,
			resource_id = $resource_id,
			status = $status,
			client_ip = $client_ip,
			reqid = $reqid,
			time_stamp = <datetime>$time_stamp,
			expires_at = <datetime>$expires_at`,
		vars,
	)
	if err != nil {
		log.Printf("[audit] Write failed: %v (event: %s %s tenant=%s)", err, ev.Action, ev.Status, tenantID)
	}
}

// LogEvent writes a single audit event directly (synchronous, for testing).
// Validates tenant_id before writing.
func (r *AuditRepo) LogEvent(ctx context.Context, event *audit.SecurityEvent, expectedTenantID string) error {
	if event.TenantID == "" {
		return fmt.Errorf("audit event TenantID is empty")
	}
	if expectedTenantID != "" && event.TenantID != expectedTenantID {
		return fmt.Errorf("audit tenant mismatch: expected %s, got %s", expectedTenantID, event.TenantID)
	}
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}

	now := time.Now()
	vars := map[string]any{
		"user_id":       event.UserID,
		"tenant_id":     event.TenantID,
		"masked_email":  event.MaskedEmail,
		"action":        event.Action,
		"resource_type": event.ResourceType,
		"resource_id":   event.ResourceID,
		"status":        event.Status,
		"client_ip":     event.ClientIP,
		"reqid":         event.ReqID,
		"time_stamp":    now.Format(time.RFC3339),
		"expires_at":    now.AddDate(2, 0, 0).Format(time.RFC3339),
	}

	_, err := r.pool.Query(ctx, "audit", event.TenantID,
		`CREATE security_audit SET
			user_id = $user_id,
			tenant_id = $tenant_id,
			masked_email = $masked_email,
			action = $action,
			resource_type = $resource_type,
			resource_id = $resource_id,
			status = $status,
			client_ip = $client_ip,
			reqid = $reqid,
			time_stamp = <datetime>$time_stamp,
			expires_at = <datetime>$expires_at`,
		vars,
	)
	if err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	return nil
}

// GetEvents reads audit events for a tenant/user (read-only, for admin UI).
func (r *AuditRepo) GetEvents(ctx context.Context, tenantID, userID string, limit int) ([]*audit.SecurityEvent, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if limit <= 0 {
		limit = 50
	}
	vars := map[string]any{"limit": limit}
	q := "SELECT * FROM security_audit"
	if userID != "" {
		q += " WHERE user_id = $user_id"
		vars["user_id"] = userID
	}
	q += " ORDER BY time_stamp DESC LIMIT $limit"

	results, err := r.pool.Query(ctx, "audit", tenantID, q, vars)
	if err != nil {
		return nil, err
	}
	rows := firstRows(results)
	var events []*audit.SecurityEvent
	for _, row := range rows {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		events = append(events, mapAuditRow(rm))
	}
	return events, nil
}

func mapAuditRow(rm map[string]any) *audit.SecurityEvent {
	ev := &audit.SecurityEvent{}
	if v, ok := rm["user_id"].(string); ok {
		ev.UserID = v
	}
	if v, ok := rm["tenant_id"].(string); ok {
		ev.TenantID = v
	}
	if v, ok := rm["masked_email"].(string); ok {
		ev.MaskedEmail = v
	}
	if v, ok := rm["action"].(string); ok {
		ev.Action = v
	}
	if v, ok := rm["resource_type"].(string); ok {
		ev.ResourceType = v
	}
	if v, ok := rm["resource_id"].(string); ok {
		ev.ResourceID = v
	}
	if v, ok := rm["status"].(string); ok {
		ev.Status = v
	}
	if v, ok := rm["client_ip"].(string); ok {
		ev.ClientIP = v
	}
	if v, ok := rm["reqid"].(string); ok {
		ev.ReqID = v
	}
	return ev
}
