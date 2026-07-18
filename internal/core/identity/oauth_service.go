// Package identity — OAuth2 service for external identity providers.
// Handles state management, token exchange, and user linking.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OAuthProvider is the interface for external identity providers (Google, Entra, Apple).
type OAuthProvider interface {
	// Name returns the provider identifier ("google", "entra", "apple").
	Name() string
	// AuthURL returns the authorization URL with state and PKCE challenge.
	AuthURL(state string, codeChallenge string) string
	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error)
	// GetUserInfo retrieves the user's profile from the provider.
	GetUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error)
}

// OAuthToken holds tokens from the provider.
type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
	TokenType    string
}

// OAuthUserInfo holds the user's profile from the provider.
type OAuthUserInfo struct {
	Provider    string // "google", "entra", "apple"
	ProviderSub string // unique ID in the provider
	Email       string
	Name        string
	Verified    bool
}

// OAuthAccount links an external identity to a local user.
type OAuthAccount struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	TenantID    string    `json:"tenant_id"`
	Provider    string    `json:"provider"`
	ProviderSub string    `json:"provider_sub"`
	CreatedAt   time.Time `json:"created_at"`
}

// OAuthAccountStore persists OAuth account links.
type OAuthAccountStore interface {
	// LinkOrCreate finds existing link by provider+sub, or creates a new one.
	// Returns the userID (existing or newly created).
	LinkOrCreate(ctx context.Context, account *OAuthAccount) (string, error)
	// FindByProvider finds an OAuth account by provider and provider_sub.
	FindByProvider(ctx context.Context, provider, providerSub string) (*OAuthAccount, error)
	// FindByUserID finds all OAuth accounts for a user.
	FindByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error)
	// Unlink removes an OAuth account link.
	Unlink(ctx context.Context, userID, provider string) error
}

// OAuthService orchestrates OAuth2 flows.
type OAuthService struct {
	providers map[string]OAuthProvider
	accounts  OAuthAccountStore
	users     UserStore
	pepper    string

	mu     sync.Mutex
	states map[string]*oauthState // state → metadata
}

type oauthState struct {
	CreatedAt     time.Time
	CodeChallenge string
	TenantID      string
	RedirectURI   string
}

// NewOAuthService creates an OAuthService.
func NewOAuthService(accounts OAuthAccountStore, users UserStore, pepper string) *OAuthService {
	return &OAuthService{
		providers: make(map[string]OAuthProvider),
		accounts:  accounts,
		users:     users,
		pepper:    pepper,
		states:    make(map[string]*oauthState),
	}
}

// RegisterProvider adds a provider to the service.
func (s *OAuthService) RegisterProvider(p OAuthProvider) {
	s.providers[p.Name()] = p
}

// BeginAuth starts the OAuth2 flow. Returns the authorization URL and state.
func (s *OAuthService) BeginAuth(providerName, tenantID, redirectURI string) (string, string, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return "", "", fmt.Errorf("unknown provider: %s", providerName)
	}

	state := generateState()
	codeChallenge := generateState() // simplified PKCE — real impl uses S256

	s.mu.Lock()
	s.states[state] = &oauthState{
		CreatedAt:     time.Now(),
		CodeChallenge: codeChallenge,
		TenantID:      tenantID,
		RedirectURI:   redirectURI,
	}
	s.mu.Unlock()

	authURL := p.AuthURL(state, codeChallenge)
	return authURL, state, nil
}

// CompleteAuth handles the callback from the provider.
func (s *OAuthService) CompleteAuth(ctx context.Context, providerName, state, code string) (*OAuthUserInfo, string, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return nil, "", fmt.Errorf("unknown provider: %s", providerName)
	}

	// Validate state
	s.mu.Lock()
	st, ok := s.states[state]
	if !ok {
		s.mu.Unlock()
		return nil, "", fmt.Errorf("invalid or expired state")
	}
	delete(s.states, state)
	s.mu.Unlock()

	if time.Since(st.CreatedAt) > 10*time.Minute {
		return nil, "", fmt.Errorf("state expired")
	}

	// Exchange code for tokens
	token, err := p.ExchangeCode(ctx, code, st.CodeChallenge)
	if err != nil {
		return nil, "", fmt.Errorf("exchange code: %w", err)
	}

	// Get user info
	info, err := p.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, "", fmt.Errorf("get user info: %w", err)
	}

	// Link or create user
	account := &OAuthAccount{
		Provider:    providerName,
		ProviderSub: info.ProviderSub,
		TenantID:    st.TenantID,
	}
	userID, err := s.accounts.LinkOrCreate(ctx, account)
	if err != nil {
		return nil, "", fmt.Errorf("link account: %w", err)
	}

	return info, userID, nil
}

// GetProviders returns registered provider names.
func (s *OAuthService) GetProviders() []string {
	var names []string
	for name := range s.providers {
		names = append(names, name)
	}
	return names
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
