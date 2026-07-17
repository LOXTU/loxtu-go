package identity

import (
	"context"
	"fmt"
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
	users UserStore
}

// NewOAuthManager constructs the OAuth domain service.
func NewOAuthManager(users UserStore) *OAuthManager {
	return &OAuthManager{users: users}
}

// LinkAndIssue resolves or creates a minimal user and issues tokens.
// Does not persist refresh — caller saves TokenPair.RefreshHash via SessionStore.
func (m *OAuthManager) LinkAndIssue(ctx context.Context, tenantNS string, ext ExternalIdentity, role string) (TokenPair, *User, error) {
	if ext.Email == "" {
		return TokenPair{}, nil, fmt.Errorf("external identity missing email")
	}
	if tenantNS == "" {
		tenantNS = "public"
	}
	if role == "" {
		role = "worker"
	}

	hash := EmailHash(ext.Email)
	user, err := m.users.FindByEmailHash(ctx, tenantNS, hash)
	if err != nil || user == nil {
		actorID, cerr := m.users.CreateMinimalUser(ctx, tenantNS, hash)
		if cerr != nil {
			return TokenPair{}, nil, fmt.Errorf("create user: %w", cerr)
		}
		user = &User{
			ActorID:   actorID,
			EmailHash: hash,
			TenantNS:  tenantNS,
			Email:     ext.Email,
			Role:      role,
			IsActive:  true,
		}
	} else {
		user.Email = ext.Email
		if user.Role == "" {
			user.Role = role
		}
	}

	pair, err := IssueTokens(ext.Email, tenantNS, user.EmployeeID, user.Role)
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
