package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour
)

// AccessClaims carries full user identity in the access JWT payload.
type AccessClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// TokenPair is the pure issuance result — persistence is the caller's (adapter) job.
type TokenPair struct {
	AccessToken  string
	RefreshPlain string
	RefreshHash  string
	ExpiresAt    time.Time // refresh expiry hint for SessionStore
}

// Session is a refresh-token session row (maps to sessions table).
type Session struct {
	UserID    string // UUID v7
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// signingKey returns HS256 secret; panics if LOXTU_JWT_SECRET unset (fail-fast).
func signingKey() []byte {
	key := os.Getenv("LOXTU_JWT_SECRET")
	if key == "" {
		panic("LOXTU_JWT_SECRET is not set in environment")
	}
	return []byte(key)
}

// IssueAccessToken creates a short-lived HS256 JWT for the given identity.
func IssueAccessToken(userID, tenantID, role string, permissions []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "loxtu",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:      userID,
		TenantID:    tenantID,
		Role:        role,
		Permissions: permissions,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey())
}

// ValidateAccessToken parses and validates an access JWT.
func ValidateAccessToken(raw string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey(), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// IssueRefreshToken generates an opaque 32-byte refresh token and its SHA-256 hash.
func IssueRefreshToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(sum[:])
	return plain, hash, nil
}

// HashToken returns SHA-256 hex of s (refresh token hashing).
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// IssueTokens creates access + refresh tokens.
// Does NOT write to DB — returns RefreshHash for SessionStore.
func IssueTokens(userID, tenantID, role string, permissions []string, accessTTL time.Duration) (pair TokenPair, err error) {
	access, err := IssueAccessToken(userID, tenantID, role, permissions, accessTTL)
	if err != nil {
		return TokenPair{}, fmt.Errorf("access token: %w", err)
	}
	plain, hash, err := IssueRefreshToken()
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh token: %w", err)
	}
	return TokenPair{
		AccessToken:  access,
		RefreshPlain: plain,
		RefreshHash:  hash,
		ExpiresAt:    time.Now().Add(RefreshTokenTTL),
	}, nil
}
