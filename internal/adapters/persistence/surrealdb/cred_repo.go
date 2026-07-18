package surrealdb

import (
	"context"
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

// SaveCredential upserts a passkey credential.
func (r *CredRepo) SaveCredential(ctx context.Context, ns, actorID string, cred *webauthn.Credential) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	if cred == nil {
		return fmt.Errorf("nil credential")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return fmt.Errorf("invalid actor id: %s", actorID)
	}
	_, err := r.pool.Query(ctx, ns, ns,
		`DELETE passkey_credentials WHERE kid = $kid AND actor_id = $actor;
CREATE passkey_credentials SET actor_id = $actor, kid = $kid, public_key = $pk, sign_count = $sc, transports = $trans, backup_eligible = $be, backup_state = $bs`,
		map[string]any{
			"actor": actor,
			"kid":   cred.ID,
			"pk":    cred.PublicKey,
			"sc":    int(cred.Authenticator.SignCount),
			"trans": cred.Transport,
			"be":    cred.Flags.BackupEligible,
			"bs":    cred.Flags.BackupState,
		},
	)
	return err
}

// FindByHandle resolves passkey_users by handle and loads credentials.
// NOTE: SurrealDB Go SDK bytes comparison may not match raw []byte via WHERE.
// For discoverable login, prefer FindByCredentialID (kid lookup) instead.
func (r *CredRepo) FindByHandle(ctx context.Context, ns string, handle []byte) (*identity.PasskeyUser, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT actor_id, handle, email FROM passkey_users WHERE handle = $handle LIMIT 1",
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
	actorID := formatRecordID(rm["actor_id"])
	email, _ := rm["email"].(string)
	h := asBytes(rm["handle"])
	if len(h) == 0 {
		h = handle
	}
	creds, _ := r.queryCredentials(ctx, ns, actorID)
	return &identity.PasskeyUser{
		Email:       email,
		TenantNS:    ns,
		Handle:      h,
		ActorID:     actorID,
		Credentials: creds,
	}, nil
}

// FindByCredentialID resolves passkey_users by credential kid (rawID).
// Used for discoverable login — avoids bytes-comparison issues with handle.
func (r *CredRepo) FindByCredentialID(ctx context.Context, ns string, credentialID []byte) (*identity.PasskeyUser, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	// Step 1: find credential by kid
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT actor_id FROM passkey_credentials WHERE kid = $kid LIMIT 1",
		map[string]any{"kid": credentialID},
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
	actorID := formatRecordID(rm["actor_id"])
	if actorID == "" {
		return nil, nil
	}
	// Step 2: load passkey_user by actor_id
	return r.FindPasskeyUserByActor(ctx, ns, actorID)
}

// UpsertPasskeyUser creates or updates passkey_users row.
func (r *CredRepo) UpsertPasskeyUser(ctx context.Context, ns, actorID, email string, handle []byte) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return fmt.Errorf("invalid actor id: %s", actorID)
	}
	_, err := r.pool.Query(ctx, ns, ns,
		"UPSERT passkey_users CONTENT { actor_id: $actor, handle: $handle, email: $email }",
		map[string]any{"actor": actor, "handle": handle, "email": email},
	)
	return err
}

// FindPasskeyUserByActor loads passkey user + credentials by actorID.
func (r *CredRepo) FindPasskeyUserByActor(ctx context.Context, ns, actorID string) (*identity.PasskeyUser, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return nil, fmt.Errorf("invalid actor id: %s", actorID)
	}
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT * FROM passkey_users WHERE actor_id = $actor LIMIT 1",
		map[string]any{"actor": actor},
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
	email, _ := rm["email"].(string)
	handle := asBytes(rm["handle"])
	creds, _ := r.queryCredentials(ctx, ns, actorID)
	return &identity.PasskeyUser{
		Email:       email,
		TenantNS:    ns,
		Handle:      handle,
		ActorID:     actorID,
		Credentials: creds,
	}, nil
}

// UpdateSignCount updates authenticator sign counter.
func (r *CredRepo) UpdateSignCount(ctx context.Context, ns, actorID string, kid []byte, newCount int) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return fmt.Errorf("invalid actor id: %s", actorID)
	}
	_, err := r.pool.Query(ctx, ns, ns,
		"UPDATE passkey_credentials SET sign_count = $sc WHERE actor_id = $actor AND kid = $kid",
		map[string]any{"actor": actor, "kid": kid, "sc": newCount},
	)
	return err
}

func (r *CredRepo) queryCredentials(ctx context.Context, ns, actorID string) ([]webauthn.Credential, error) {
	if actorID == "" {
		return nil, nil
	}
	actor := getRecordID(actorID)
	if actor == nil {
		return nil, nil
	}
	results, err := r.pool.Query(ctx, ns, ns,
		"SELECT * FROM passkey_credentials WHERE actor_id = $actor",
		map[string]any{"actor": actor},
	)
	if err != nil {
		return nil, err
	}
	rows := firstRows(results)
	var creds []webauthn.Credential
	for _, row := range rows {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		c := webauthn.Credential{}
		c.ID = asBytes(rm["kid"])
		c.PublicKey = asBytes(rm["public_key"])
		switch sc := rm["sign_count"].(type) {
		case float64:
			c.Authenticator.SignCount = uint32(sc)
		case int64:
			c.Authenticator.SignCount = uint32(sc)
		case int:
			c.Authenticator.SignCount = uint32(sc)
		}
		if be, ok := rm["backup_eligible"].(bool); ok {
			c.Flags.BackupEligible = be
		}
		if bs, ok := rm["backup_state"].(bool); ok {
			c.Flags.BackupState = bs
		}
		if trans, ok := rm["transports"].([]any); ok {
			for _, t := range trans {
				if ts, ok := t.(string); ok {
					c.Transport = append(c.Transport, protocol.AuthenticatorTransport(ts))
				}
			}
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func asBytes(v any) []byte {
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	default:
		return nil
	}
}
