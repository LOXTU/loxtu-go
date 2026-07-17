package identity

import (
	"context"
	"fmt"
	"time"
)

// SessionAuthService orchestrates token issuance with session persistence.
// Pure crypto/JWT stays in IssueTokens / IssueAccessToken (session.go).
// This type only calls UserStore + SessionStore ports — never SurrealDB/SQL.
type SessionAuthService struct {
	users    UserStore
	sessions SessionStore
}

// TokenService is an alias for SessionAuthService (handler constructors).
type TokenService = SessionAuthService

// NewTokenService wires ports (no DB driver).
func NewTokenService(users UserStore, sessions SessionStore) *SessionAuthService {
	return NewSessionAuthService(users, sessions)
}

// NewSessionAuthService constructs the session/auth application service.
func NewSessionAuthService(users UserStore, sessions SessionStore) *SessionAuthService {
	return &SessionAuthService{users: users, sessions: sessions}
}

// Issue creates access+refresh tokens only (no persistence).
func (s *SessionAuthService) Issue(email, tenantNS, employeeID, role string) (TokenPair, error) {
	if tenantNS == "" {
		tenantNS = "public"
	}
	if role == "" {
		role = "worker"
	}
	return IssueTokens(email, tenantNS, employeeID, role)
}

// IssueSession creates tokens and persists refresh hash via SessionStore (one-session policy).
func (s *SessionAuthService) IssueSession(ctx context.Context, email, tenantNS, employeeID, role string) (TokenPair, error) {
	pair, err := s.Issue(email, tenantNS, employeeID, role)
	if err != nil {
		return TokenPair{}, err
	}
	if s.sessions == nil || s.users == nil {
		return pair, nil
	}
	u, err := s.users.FindByEmailHash(ctx, tenantNS, EmailHash(email))
	if err != nil || u == nil || u.ActorID == "" {
		return pair, nil
	}
	if err := s.sessions.SaveRefreshToken(ctx, tenantNS, u.ActorID, pair.RefreshHash, pair.ExpiresAt); err != nil {
		return pair, fmt.Errorf("save session: %w", err)
	}
	return pair, nil
}

// Rotate validates refresh hash, revokes old session, issues new pair via ports only.
func (s *SessionAuthService) Rotate(ctx context.Context, tenantNS, oldPlain string) (TokenPair, error) {
	if s.sessions == nil {
		return TokenPair{}, fmt.Errorf("sessions not configured")
	}
	if tenantNS == "" {
		tenantNS = "public"
	}
	oldHash := HashToken(oldPlain)
	sess, err := s.sessions.FindSessionByHash(ctx, tenantNS, oldHash)
	if err != nil || sess == nil {
		return TokenPair{}, fmt.Errorf("session not found")
	}
	email := sess.Email
	actorID := sess.ActorID
	if email == "" && s.users != nil && actorID != "" {
		if u, err := s.users.FindByActorID(ctx, tenantNS, actorID); err == nil && u != nil {
			email = u.Email
		}
	}
	_ = s.sessions.RevokeAllSessions(ctx, tenantNS, actorID)
	if email == "" {
		return TokenPair{}, fmt.Errorf("session actor has no email")
	}
	return s.IssueSession(ctx, email, tenantNS, "", "worker")
}

// RevokeAllForEmail deletes all refresh sessions for the user (ports only).
func (s *SessionAuthService) RevokeAllForEmail(ctx context.Context, tenantNS, email string) error {
	if s.users == nil || s.sessions == nil {
		return nil
	}
	if tenantNS == "" {
		tenantNS = "public"
	}
	u, err := s.users.FindByEmailHash(ctx, tenantNS, EmailHash(email))
	if err != nil || u == nil {
		return fmt.Errorf("user not found for %s", email)
	}
	return s.sessions.RevokeAllSessions(ctx, tenantNS, u.ActorID)
}

// DefaultRefreshTTL for callers saving sessions manually.
const DefaultRefreshTTL = 30 * 24 * time.Hour
