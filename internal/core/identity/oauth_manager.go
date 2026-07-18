package identity

import (
	"context"
	"fmt"
	"time"
)

// ExternalIdentity is a normalised profile from Google / Apple / Entra adapters.
type ExternalIdentity struct {
	Provider   string // "google" | "apple" | "entra"
	Subject    string
	Email      string
	Name       string
	TenantHint string
	Groups     []string
}

// OAuthManager links external IdPs to LOXTU users and issues tokens.
type OAuthManager struct {
	users    UserStore
	sessions SessionStore
}

// NewOAuthManager constructs the OAuth domain service.
func NewOAuthManager(users UserStore, sessions SessionStore) *OAuthManager {
	return &OAuthManager{users: users, sessions: sessions}
}

// LinkAndIssue resolves or creates a user and issues tokens.
func (m *OAuthManager) LinkAndIssue(ctx context.Context, tenantID string, ext ExternalIdentity, role string) (TokenPair, *User, error) {
	if ext.Email == "" {
		return TokenPair{}, nil, fmt.Errorf("external identity missing email")
	}
	if tenantID == "" {
		tenantID = "public"
	}
	if role == "" {
		role = "worker"
	}

	hash := EmailHash(ext.Email)
	user, err := m.users.FindByEmailHash(ctx, hash)
	if err != nil || user == nil {
		// Create minimal user
		user = &User{
			UserID:    generateUUIDv7(),
			EmailHash: hash,
			TenantID:  tenantID,
			Role:      role,
			Status:    "active",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if cerr := m.users.Create(ctx, user); cerr != nil {
			return TokenPair{}, nil, fmt.Errorf("create user: %w", cerr)
		}
	} else {
		if user.Role == "" {
			user.Role = role
		}
	}

	pair, err := IssueTokens(user.UserID, tenantID, user.Role, user.Permissions, AccessTokenTTL)
	if err != nil {
		return TokenPair{}, nil, err
	}
	return pair, user, nil
}

// MapEntraGroups maps Microsoft groups → LOXTU role (stub for adapters).
func MapEntraGroups(groups []string) string {
	for _, g := range groups {
		switch g {
		case "LOXTU-Admin", "Admin":
			return "admin"
		case "LOXTU-Manager", "Manager":
			return "manager"
		}
	}
	return "worker"
}

// generateUUIDv7 is a placeholder — real impl uses google/uuid.
// Adapters will call uuid.New() directly; this is for core-only compilation.
func generateUUIDv7() string {
	// Placeholder — composition root wires real UUID generation.
	return fmt.Sprintf("placeholder-uuid-v7")
}
