package surrealdb

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/audit"
)

const (
	AuditNS = "loxtu"
	AuditDB = "loxtu"

	auditQueueSize   = 1024
	auditWorkerCount = 5
)

// AuditRepo implements audit.Store with an async worker pool.
// NewAuditRepo starts workers immediately (no separate Start call required).
// Implements audit.Lifecycle via Start/Stop for graceful shutdown.
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
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
		if rec := getRecordID(ev.ActorID); rec != nil {
			q = "CREATE security_audit SET actor_id = $actor_id, actor_email_masked = $actor_email_masked, action = $action, resource_type = $resource_type, resource_id = $resource_id, status = $status, client_ip = $client_ip, reqid = $reqid, time_stamp = <datetime>$time_stamp, expires_at = <datetime>$expires_at"
			vars["actor_id"] = rec
		}
	}

	_, err := r.pool.Query(ctx, AuditNS, AuditDB, q, vars)
	if err != nil {
		log.Printf("[audit] Write failed: %v (event: %s %s)", err, ev.Action, ev.Status)
	}
}
