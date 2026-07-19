package surrealdb

import (
	"context"
	"fmt"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// SessionRepo implements identity.SessionStore — returns *identity.Session.
type SessionRepo struct {
	pool *Pool
}

// NewSessionRepo constructs a SessionStore adapter.
func NewSessionRepo(pool *Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

var _ identity.SessionStore = (*SessionRepo)(nil)

// Create persists a new session (revokes prior for same user first).
func (r *SessionRepo) Create(ctx context.Context, session *identity.Session) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	// Revoke prior sessions for this user (one-session policy)
	if session.UserID != "" {
		_ = r.RevokeByUserID(ctx, session.UserID)
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`CREATE sessions SET user_id = $uid, token_hash = $hash, expires_at = time::from_unix($expires), created_at = time::now()`,
		map[string]any{
			"uid":     session.UserID,
			"hash":    session.TokenHash,
			"expires": session.ExpiresAt.Unix(),
		},
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// FindByTokenHash looks up a session by hashed refresh token.
func (r *SessionRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*identity.Session, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM sessions WHERE token_hash = $hash LIMIT 1",
		map[string]any{"hash": tokenHash},
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
	sess := &identity.Session{
		TokenHash: tokenHash,
	}
	if uid, ok := rm["user_id"].(string); ok {
		sess.UserID = uid
	}
	if exp, ok := parseTime(rm["expires_at"]); ok {
		sess.ExpiresAt = exp
	}
	if cr, ok := parseTime(rm["created_at"]); ok {
		sess.CreatedAt = cr
	}
	return sess, nil
}

// RevokeByUserID deletes all sessions for a user.
func (r *SessionRepo) RevokeByUserID(ctx context.Context, userID string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE sessions WHERE user_id = $uid",
		map[string]any{"uid": userID},
	)
	return err
}

// RevokeByTokenHash deletes a session by its token hash.
func (r *SessionRepo) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE sessions WHERE token_hash = $hash",
		map[string]any{"hash": tokenHash},
	)
	return err
}

// CleanupExpired removes expired sessions.
func (r *SessionRepo) CleanupExpired(ctx context.Context) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"DELETE sessions WHERE expires_at < time::now()",
		nil,
	)
	return err
}

func parseTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		tt, err := time.Parse(time.RFC3339, t)
		return tt, err == nil
	default:
		return time.Time{}, false
	}
}
