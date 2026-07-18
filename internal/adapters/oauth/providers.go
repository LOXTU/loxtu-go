// Package oauth provides OAuth2 adapters for external identity providers.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// ProviderConfig holds OAuth2 configuration for a provider.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// ── Google ──────────────────────────────────────────────────────────────

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleUserURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleProvider implements identity.OAuthProvider for Google.
type GoogleProvider struct {
	cfg ProviderConfig
}

// NewGoogleProvider creates a Google OAuth2 provider.
func NewGoogleProvider(cfg ProviderConfig) *GoogleProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	return &GoogleProvider{cfg: cfg}
}

func (g *GoogleProvider) Name() string { return "google" }

func (g *GoogleProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":             {g.cfg.ClientID},
		"redirect_uri":          {g.cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(g.cfg.Scopes, " ")},
		"state":                 {state},
		"access_type":           {"offline"},
		"prompt":                {"consent"},
	}
	return googleAuthURL + "?" + params.Encode()
}

func (g *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*identity.OAuthToken, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"redirect_uri":  {g.cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &identity.OAuthToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		ExpiresIn:    token.ExpiresIn,
		TokenType:    token.TokenType,
	}, nil
}

func (g *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*identity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", googleUserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo failed: %d", resp.StatusCode)
	}

	var user struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Verified bool  `json:"verified_email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &identity.OAuthUserInfo{
		Provider:    "google",
		ProviderSub: user.ID,
		Email:       user.Email,
		Name:        user.Name,
		Verified:    user.Verified,
	}, nil
}

// ── Microsoft Entra ─────────────────────────────────────────────────────

const (
	entraAuthURL  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	entraTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	entraUserURL  = "https://graph.microsoft.com/v1.0/me"
)

// EntraProvider implements identity.OAuthProvider for Microsoft Entra (Azure AD).
type EntraProvider struct {
	cfg ProviderConfig
}

// NewEntraProvider creates a Microsoft Entra OAuth2 provider.
func NewEntraProvider(cfg ProviderConfig) *EntraProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile", "User.Read"}
	}
	return &EntraProvider{cfg: cfg}
}

func (e *EntraProvider) Name() string { return "entra" }

func (e *EntraProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":     {e.cfg.ClientID},
		"redirect_uri":  {e.cfg.RedirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(e.cfg.Scopes, " ")},
		"state":         {state},
		"response_mode": {"query"},
	}
	return entraAuthURL + "?" + params.Encode()
}

func (e *EntraProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*identity.OAuthToken, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {e.cfg.ClientID},
		"client_secret": {e.cfg.ClientSecret},
		"redirect_uri":  {e.cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", entraTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("entra token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &identity.OAuthToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		ExpiresIn:    token.ExpiresIn,
		TokenType:    token.TokenType,
	}, nil
}

func (e *EntraProvider) GetUserInfo(ctx context.Context, accessToken string) (*identity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", entraUserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entra userinfo failed: %d", resp.StatusCode)
	}

	var user struct {
		ID                string `json:"id"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	email := user.Mail
	if email == "" {
		email = user.UserPrincipalName
	}

	return &identity.OAuthUserInfo{
		Provider:    "entra",
		ProviderSub: user.ID,
		Email:       email,
		Name:        user.DisplayName,
		Verified:    true,
	}, nil
}

// ── Apple ───────────────────────────────────────────────────────────────

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
)

// AppleProvider implements identity.OAuthProvider for Apple Sign In.
type AppleProvider struct {
	cfg ProviderConfig
}

// NewAppleProvider creates an Apple Sign In OAuth2 provider.
func NewAppleProvider(cfg ProviderConfig) *AppleProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"name", "email"}
	}
	return &AppleProvider{cfg: cfg}
}

func (a *AppleProvider) Name() string { return "apple" }

func (a *AppleProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":     {a.cfg.ClientID},
		"redirect_uri":  {a.cfg.RedirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(a.cfg.Scopes, " ")},
		"state":         {state},
		"response_mode": {"form_post"},
	}
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}
	return appleAuthURL + "?" + params.Encode()
}

func (a *AppleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*identity.OAuthToken, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"redirect_uri":  {a.cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", appleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("apple token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &identity.OAuthToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		ExpiresIn:    token.ExpiresIn,
		TokenType:    token.TokenType,
	}, nil
}

func (a *AppleProvider) GetUserInfo(ctx context.Context, accessToken string) (*identity.OAuthUserInfo, error) {
	// Apple doesn't have a userinfo endpoint — info comes from the ID token.
	// For simplicity, return minimal info. Real impl would decode the ID token JWT.
	return &identity.OAuthUserInfo{
		Provider:    "apple",
		ProviderSub: "", // decoded from ID token
		Email:       "", // decoded from ID token
		Verified:    true,
	}, nil
}
