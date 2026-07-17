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

// SaveRefreshToken revokes prior sessions for actor then creates a new one.
func (r *SessionRepo) SaveRefreshToken(ctx context.Context, ns, actorID, tokenHash string, expires time.Time) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return fmt.Errorf("invalid actor id: %s", actorID)
	}
	if err := r.RevokeAllSessions(ctx, ns, actorID); err != nil {
		return fmt.Errorf("revoke prior: %w", err)
	}
	_, err := r.pool.Query(ctx, ns, ns,
		`CREATE sessions SET actor_id = $actor, token_hash = $hash, expires_at = time::from_unix($expires), created_at = time::now()`,
		map[string]any{
			"actor":   actor,
			"hash":    tokenHash,
			"expires": expires.Unix(),
		},
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// RevokeAllSessions deletes all sessions for actorID in ns.
func (r *SessionRepo) RevokeAllSessions(ctx context.Context, ns, actorID string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return fmt.Errorf("invalid actor id: %s", actorID)
	}
	_, err := r.pool.Query(ctx, ns, ns,
		"DELETE sessions WHERE actor_id = $actor",
		map[string]any{"actor": actor},
	)
	return err
}

// FindSessionByHash looks up a session by hashed refresh token.
func (r *SessionRepo) FindSessionByHash(ctx context.Context, ns, tokenHash string) (*identity.Session, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, ns, ns,
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
		return nil, fmt.Errorf("unexpected session row type %T", rows[0])
	}

	sess := &identity.Session{
		TokenHash: tokenHash,
		ActorID:   formatRecordID(rm["actor_id"]),
	}
	if exp, ok := parseTime(rm["expires_at"]); ok {
		sess.ExpiresAt = exp
	}
	if cr, ok := parseTime(rm["created_at"]); ok {
		sess.CreatedAt = cr
	}
	return sess, nil
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
