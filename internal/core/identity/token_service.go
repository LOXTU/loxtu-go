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
	accessTTL time.Duration
}

// TokenService is an alias for SessionAuthService (handler constructors).
type TokenService = SessionAuthService

// NewTokenService wires ports (no DB driver).
func NewTokenService(users UserStore, sessions SessionStore) *SessionAuthService {
	return NewSessionAuthService(users, sessions)
}

// NewSessionAuthService constructs the session/auth application service.
func NewSessionAuthService(users UserStore, sessions SessionStore) *SessionAuthService {
	return &SessionAuthService{
		users:     users,
		sessions:  sessions,
		accessTTL: AccessTokenTTL,
	}
}

// SetAccessTTL overrides the default access token TTL (from tenant security policy).
func (s *SessionAuthService) SetAccessTTL(d time.Duration) {
	s.accessTTL = d
}

// Issue creates access+refresh tokens only (no persistence).
func (s *SessionAuthService) Issue(userID, tenantID, role string, permissions []string) (TokenPair, error) {
	if tenantID == "" {
		tenantID = "public"
	}
	if role == "" {
		role = "worker"
	}
	return IssueTokens(userID, tenantID, role, permissions, s.accessTTL)
}

// IssueSession creates tokens and persists refresh hash via SessionStore.
func (s *SessionAuthService) IssueSession(ctx context.Context, userID, tenantID, role string, permissions []string) (TokenPair, error) {
	pair, err := s.Issue(userID, tenantID, role, permissions)
	if err != nil {
		return TokenPair{}, err
	}
	if s.sessions == nil {
		return pair, nil
	}
	if err := s.sessions.Create(ctx, &Session{
		UserID:    userID,
		TokenHash: pair.RefreshHash,
		ExpiresAt: pair.ExpiresAt,
		CreatedAt: time.Now(),
	}); err != nil {
		return pair, fmt.Errorf("save session: %w", err)
	}
	return pair, nil
}

// Rotate validates refresh hash, revokes old session, issues new pair.
func (s *SessionAuthService) Rotate(ctx context.Context, oldPlain string) (TokenPair, error) {
	if s.sessions == nil {
		return TokenPair{}, fmt.Errorf("sessions not configured")
	}
	oldHash := HashToken(oldPlain)
	sess, err := s.sessions.FindByTokenHash(ctx, oldHash)
	if err != nil || sess == nil {
		return TokenPair{}, fmt.Errorf("session not found")
	}
	_ = s.sessions.RevokeByUserID(ctx, sess.UserID)

	if s.users == nil {
		return TokenPair{}, fmt.Errorf("users not configured")
	}
	u, err := s.users.FindByUserID(ctx, sess.UserID)
	if err != nil || u == nil {
		return TokenPair{}, fmt.Errorf("user not found for session")
	}
	return s.IssueSession(ctx, u.UserID, u.TenantID, u.Role, u.Permissions)
}

// RevokeAllForUser deletes all refresh sessions for the user.
func (s *SessionAuthService) RevokeAllForUser(ctx context.Context, userID string) error {
	if s.sessions == nil {
		return nil
	}
	return s.sessions.RevokeByUserID(ctx, userID)
}

// DefaultRefreshTTL for callers saving sessions manually.
const DefaultRefreshTTL = 30 * 24 * time.Hour
