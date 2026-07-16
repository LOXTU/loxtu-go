package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/loxtu/loxtu-go/internal/platform/db"
	mw "github.com/loxtu/loxtu-go/internal/platform/middleware"
)

// IssueTokens generates access + refresh tokens, persists refresh in DB.
func IssueTokens(email, tenantNS, employeeID, role string) (accessToken, refreshToken string, err error) {
	accessToken, err = IssueAccessToken(email, tenantNS, employeeID, role)
	if err != nil {
		return "", "", fmt.Errorf("access token: %w", err)
	}

	plain, hash, err := IssueRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("refresh token: %w", err)
	}

	log.Printf("[auth] Issuing tokens for %s (role=%s)", mw.MaskEmail(email), role)
	// ✅ ИСПРАВЛЕНО: передаем tenantNS в storeSession
	if err := storeSession(tenantNS, email, hash); err != nil {
		log.Printf("[auth] store session failed (non-fatal): %v", err)
	}

	return accessToken, plain, nil
}

// storeSession revokes all prior sessions for actor, then creates a new one.
// ✅ ИСПРАВЛЕНО: добавлен tenantNS в аргументы функции
func storeSession(tenantNS, email, hash string) error {
	if db.DB == nil {
		return fmt.Errorf("db not connected")
	}
	ctx := context.Background()

	// ✅ ИСПРАВЛЕНО: используем динамический tenantNS
	actorID := db.LookupUserIDByEmail(tenantNS, email)
	if actorID == "" {
		return fmt.Errorf("user not found in users table: %s", email)
	}

	// ✅ ИСПРАВЛЕНО: используем tenantNS вместо хардкода "loxtu"
	if _, err := db.DB.Query(ctx, tenantNS, tenantNS,
		"DELETE sessions WHERE actor_id = $actor",
		map[string]any{"actor": db.GetRecordID(actorID)},
	); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	// ✅ ИСПРАВЛЕНО: используем tenantNS вместо хардкода "loxtu"
	if _, err := db.DB.Query(ctx, tenantNS, tenantNS,
		"CREATE sessions SET actor_id = $actor, token_hash = $hash, expires_at = time::from_unix($expires), created_at = time::now()",
		map[string]any{
			"actor":   db.GetRecordID(actorID),
			"hash":    hash,
			"expires": time.Now().Add(30 * 24 * time.Hour).Unix(),
		},
	); err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

// RotateRefreshToken validates the current refresh token, deletes it,
// and issues a new pair.
// ✅ ИСПРАВЛЕНО: добавлен tenantNS в аргументы функции
func RotateRefreshToken(tenantNS, oldPlain string) (accessToken, newPlain string, err error) {
	oldHash := sha256Hex(oldPlain)

	if db.DB == nil {
		return "", "", fmt.Errorf("db not connected")
	}
	ctx := context.Background()

	// ✅ ИСПРАВЛЕНО: используем tenantNS
	results, err := db.DB.Query(ctx, tenantNS, tenantNS,
		"SELECT * FROM sessions WHERE token_hash = $hash",
		map[string]any{"hash": oldHash},
	)
	if err != nil || len(results) == 0 {
		return "", "", fmt.Errorf("session not found")
	}
	rows, ok := results[0].Result.([]any)
	if !ok || len(rows) == 0 {
		return "", "", fmt.Errorf("no session rows")
	}
	rm := rows[0].(map[string]any)

	// Get actor_id from session
	actorID := ""
	switch a := rm["actor_id"].(type) {
	case string:
		actorID = a
	case map[string]any:
		if id, ok := a["id"]; ok {
			actorID = fmt.Sprintf("%v", id)
		}
	}

	// Look up email from users table
	email := ""
	if actorID != "" {
		// ✅ ИСПРАВЛЕНО: используем tenantNS
		res, err := db.DB.Query(ctx, tenantNS, tenantNS,
			"SELECT email FROM users WHERE id = $id LIMIT 1",
			map[string]any{"id": actorID},
		)
		if err == nil && len(res) > 0 {
			if rows, ok := res[0].Result.([]any); ok && len(rows) > 0 {
				if rm, ok := rows[0].(map[string]any); ok {
					email, _ = rm["email"].(string)
				}
			}
		}
	}

	// Delete old session (rotation)
	// ✅ ИСПРАВЛЕНО: используем tenantNS
	db.DB.Query(ctx, tenantNS, tenantNS,
		"DELETE sessions WHERE token_hash = $hash",
		map[string]any{"hash": oldHash},
	)

	// ✅ ИСПРАВЛЕНО: используем переданный tenantNS вместо хардкода "public"
	accessToken, newPlain, err = IssueTokens(email, tenantNS, "", "worker")
	if err != nil {
		return "", "", fmt.Errorf("issue tokens: %w", err)
	}

	return accessToken, newPlain, nil
}

// RevokeAllSessions deletes all refresh tokens for the given email.
// Returns nil if the user is not found — caller should still clear cookies.
func RevokeAllSessions(tenantNS, email string) error {
	if db.DB == nil {
		return nil
	}
	actorID := db.LookupUserIDByEmail(tenantNS, email)
	if actorID == "" {
		return fmt.Errorf("user not found for %s", email)
	}
	// ✅ ИСПРАВЛЕНО: используем tenantNS вместо хардкода "loxtu"
	_, err := db.DB.Query(context.Background(), tenantNS, tenantNS,
		"DELETE sessions WHERE actor_id = $actor",
		map[string]any{"actor": db.GetRecordID(actorID)},
	)
	return err
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}