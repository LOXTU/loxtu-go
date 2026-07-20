package surrealdb

import (
	"context"
	"fmt"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// SurrealOTPRepo implements identity.OTPStore with SurrealDB KV lookup.
// Document ID: otp_codes:[user_id_hash] — single document per user.
type SurrealOTPRepo struct {
	pool *Pool
}

// NewSurrealOTPRepo constructs an OTPStore adapter.
func NewSurrealOTPRepo(pool *Pool) *SurrealOTPRepo {
	return &SurrealOTPRepo{pool: pool}
}

var _ identity.OTPStore = (*SurrealOTPRepo)(nil)

// Save creates or replaces the OTP record for a user (UPSERT by user_id_hash).
// Uses SET syntax (SCHEMAFULL-safe — no CONTENT, no hidden Go fields).
func (r *SurrealOTPRepo) Save(ctx context.Context, userIDHash, codeHash string, expiresAt time.Time) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	// Delete any existing OTP first, then CREATE with explicit SET
	_, _ = r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE type::record(\"otp_codes\", $uid)",
		map[string]any{"uid": userIDHash},
	)
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`CREATE type::record("otp_codes", $uid) SET
			user_id_hash = $uid,
			code_hash = $code_hash,
			attempts = $attempts,
			expires_at = $expires_at,
			created_at = time::now()`,
		map[string]any{
			"uid":        userIDHash,
			"code_hash":  codeHash,
			"attempts":   0,
			"expires_at": expiresAt.Unix(),
		},
	)
	if err != nil {
		return fmt.Errorf("save otp: %w", err)
	}
	return nil
}

// Get retrieves the active OTP record by user_id_hash.
func (r *SurrealOTPRepo) Get(ctx context.Context, userIDHash string) (codeHash string, attempts int, expiresAt time.Time, err error) {
	if r.pool == nil {
		return "", 0, time.Time{}, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM type::record(\"otp_codes\", $uid)",
		map[string]any{"uid": userIDHash},
	)
	if err != nil {
		return "", 0, time.Time{}, fmt.Errorf("get otp: %w", err)
	}
	rows := firstRows(results)
	if len(rows) == 0 {
		return "", 0, time.Time{}, fmt.Errorf("otp not found")
	}
	rm, ok := rows[0].(map[string]any)
	if !ok {
		return "", 0, time.Time{}, fmt.Errorf("invalid row")
	}
	if v, ok := rm["code_hash"].(string); ok {
		codeHash = v
	}
	if v, ok := rm["attempts"].(float64); ok {
		attempts = int(v)
	}
	if v, ok := rm["expires_at"].(string); ok {
		expiresAt, _ = time.Parse(time.RFC3339, v)
	}
	return codeHash, attempts, expiresAt, nil
}

// IncrementAttempts increments the failed attempt counter.
func (r *SurrealOTPRepo) IncrementAttempts(ctx context.Context, userIDHash string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"UPDATE type::record(\"otp_codes\", $uid) SET attempts += 1",
		map[string]any{"uid": userIDHash},
	)
	if err != nil {
		return fmt.Errorf("increment otp attempts: %w", err)
	}
	return nil
}

// Delete removes the OTP record (after successful verification or expiry).
func (r *SurrealOTPRepo) Delete(ctx context.Context, userIDHash string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE type::record(\"otp_codes\", $uid)",
		map[string]any{"uid": userIDHash},
	)
	if err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}
	return nil
}