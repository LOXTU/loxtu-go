package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims carries the full user identity for the JWT payload.
type AccessClaims struct {
	jwt.RegisteredClaims
	Email      string `json:"email"`
	TenantNS   string `json:"tenant_ns"`
	EmployeeID string `json:"employee_id"`
	Role       string `json:"role"`
}

func signingKey() []byte {
	key := os.Getenv("LOXTU_JWT_SECRET")
	if key == "" {
		panic("LOXTU_JWT_SECRET is not set in environment")
	}
	return []byte(key)
}

// IssueAccessToken creates a short-lived JWT for the given user.
func IssueAccessToken(email, tenantNS, employeeID, role string) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "loxtu",
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
		Email:      email,
		TenantNS:   tenantNS,
		EmployeeID: employeeID,
		Role:       role,
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

// IssueRefreshToken generates an opaque 32-byte refresh token.
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

// GetClaimsFromCookie parses the JWT from loxtu_access cookie without validation.
func GetClaimsFromCookie(r *http.Request) *AccessClaims {
	if c, err := r.Cookie("loxtu_access"); err == nil {
		token, _, _ := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(c.Value, &AccessClaims{})
		if token != nil {
			if claims, ok := token.Claims.(*AccessClaims); ok {
				return claims
			}
		}
	}
	return nil
}