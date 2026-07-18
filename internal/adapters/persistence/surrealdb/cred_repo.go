package surrealdb

import (
	"context"
	"encoding/base64"
	"strings"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// CredRepo implements identity.CredentialStore — returns *identity.PasskeyUser.
type CredRepo struct {
	pool *Pool
}

// NewCredRepo constructs a CredentialStore adapter.
func NewCredRepo(pool *Pool) *CredRepo {
	return &CredRepo{pool: pool}
}

var _ identity.CredentialStore = (*CredRepo)(nil)

// SaveUser creates a passkey_users row linking user_id → handle.
func (r *CredRepo) SaveUser(ctx context.Context, userID string, handle []byte, tenantID string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	_, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		`UPSERT passkey_users SET user_id = $uid, handle = $handle, tenant_id = $tid`,
		map[string]any{"uid": userID, "handle": handle, "tid": tenantID},
	)
	return err
}

// FindHandleByUserID loads the existing handle for a user (avoids regenerating).
func (r *CredRepo) FindHandleByUserID(ctx context.Context, userID string) ([]byte, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"SELECT handle FROM passkey_users WHERE user_id = $uid LIMIT 1",
		map[string]any{"uid": userID},
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
		return nil, nil
	}
	return asBytes(rm["handle"]), nil
}

// SaveCredential stores a passkey credential.
// kid and public_key stored as base64 strings (SurrealDB 3.2.0 CBOR bytes bug workaround).
func (r *CredRepo) SaveCredential(ctx context.Context, cred *identity.PasskeyCredential) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	if cred == nil {
		return fmt.Errorf("nil credential")
	}

	kidB64 := base64.RawURLEncoding.EncodeToString(cred.CredentialID)
	pkB64 := base64.RawURLEncoding.EncodeToString(cred.PublicKey)

	// Delete existing credential with same user_id
	_, _ = r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"DELETE passkey_credentials WHERE user_id = $uid", map[string]any{"uid": cred.UserID})

	// Format transports as SurrealDB array literal
	transStr := "[]"
	if len(cred.Transports) > 0 {
		parts := make([]string, len(cred.Transports))
		for i, t := range cred.Transports {
			parts[i] = fmt.Sprintf("'%s'", t)
		}
		transStr = "[" + strings.Join(parts, ",") + "]"
	}

	// Bypass CBOR entirely — embed all values in SQL string
	query := fmt.Sprintf(
		"CREATE passkey_credentials SET user_id = '%s', kid = '%s', public_key = '%s', sign_count = %d, transports = %s, aaguid = '%s', backup_eligible = %v, backup_state = %v",
		cred.UserID, kidB64, pkB64, cred.SignCount, transStr, cred.AAGUID, cred.BackupEligible, cred.BackupState,
	)
	_, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB, query, nil)
	return err
}

// FindCredentialsByUserID loads all credentials for a user.
func (r *CredRepo) FindCredentialsByUserID(ctx context.Context, userID string) ([]*identity.PasskeyCredential, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"SELECT * FROM passkey_credentials WHERE user_id = $uid",
		map[string]any{"uid": userID},
	)
	if err != nil {
		return nil, err
	}
	rows := firstRows(results)
	var creds []*identity.PasskeyCredential
	for _, row := range rows {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		creds = append(creds, mapCredentialRow(rm))
	}
	return creds, nil
}

// FindCredentialByKID loads a single credential by its kid (base64 string).
func (r *CredRepo) FindCredentialByKID(ctx context.Context, kid []byte) (*identity.PasskeyCredential, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	kidB64 := base64.RawURLEncoding.EncodeToString(kid)
	results, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"SELECT * FROM passkey_credentials WHERE kid = $kid LIMIT 1",
		map[string]any{"kid": kidB64},
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
		return nil, nil
	}
	return mapCredentialRow(rm), nil
}

// FindUserByHandle loads passkey_user by handle.
func (r *CredRepo) FindUserByHandle(ctx context.Context, handle []byte) (*identity.PasskeyUser, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"SELECT user_id, tenant_id, handle FROM passkey_users WHERE handle = $handle LIMIT 1",
		map[string]any{"handle": handle},
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
		return nil, nil
	}
	userID, _ := rm["user_id"].(string)
	tenantID, _ := rm["tenant_id"].(string)
	h := asBytes(rm["handle"])
	if len(h) == 0 {
		h = handle
	}
	creds, _ := r.FindCredentialsByUserID(ctx, userID)
	return &identity.PasskeyUser{
		UserID:      userID,
		TenantID:    tenantID,
		Handle:      h,
		Credentials: webauthnCredsFromDomainV2(creds),
	}, nil
}

// UpdateSignCount updates authenticator sign counter.
func (r *CredRepo) UpdateSignCount(ctx context.Context, userID string, kid []byte, newCount uint32) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	kidB64 := base64.RawURLEncoding.EncodeToString(kid)
	_, err := r.pool.Query(ctx, r.pool.defaultNS, r.pool.defaultDB,
		"UPDATE passkey_credentials SET sign_count = $sc WHERE user_id = $uid AND kid = $kid",
		map[string]any{"uid": userID, "kid": kidB64, "sc": newCount},
	)
	return err
}

// mapCredentialRow maps SurrealDB row → domain PasskeyCredential.
// kid and public_key are base64 strings in DB, decoded to []byte.
func mapCredentialRow(rm map[string]any) *identity.PasskeyCredential {
	c := &identity.PasskeyCredential{}
	// kid: base64 string → []byte
	if kidStr, ok := rm["kid"].(string); ok {
		c.CredentialID, _ = base64.RawURLEncoding.DecodeString(kidStr)
	}
	// public_key: base64 string → []byte
	if pkStr, ok := rm["public_key"].(string); ok {
		c.PublicKey, _ = base64.RawURLEncoding.DecodeString(pkStr)
	}
	c.UserID, _ = rm["user_id"].(string)
	c.AAGUID, _ = rm["aaguid"].(string)
	switch sc := rm["sign_count"].(type) {
	case float64:
		c.SignCount = uint32(sc)
	case int64:
		c.SignCount = uint32(sc)
	case uint32:
		c.SignCount = sc
	}
	if be, ok := rm["backup_eligible"].(bool); ok {
		c.BackupEligible = be
	}
	if bs, ok := rm["backup_state"].(bool); ok {
		c.BackupState = bs
	}
	if trans, ok := rm["transports"].([]any); ok {
		for _, t := range trans {
			if ts, ok := t.(string); ok {
				c.Transports = append(c.Transports, ts)
			}
		}
	}
	if ca, ok := parseTime(rm["created_at"]); ok {
		c.CreatedAt = ca
	}
	return c
}

// webauthnCredsFromDomainV2 converts domain credentials to webauthn.Credential.
func webauthnCredsFromDomainV2(creds []*identity.PasskeyCredential) []webauthn.Credential {
	var out []webauthn.Credential
	for _, c := range creds {
		out = append(out, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
				AAGUID:    []byte(c.AAGUID),
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Transport: transportFromStrings(c.Transports),
		})
	}
	return out
}

func transportFromStrings(strs []string) []protocol.AuthenticatorTransport {
	var out []protocol.AuthenticatorTransport
	for _, s := range strs {
		out = append(out, protocol.AuthenticatorTransport(s))
	}
	return out
}
