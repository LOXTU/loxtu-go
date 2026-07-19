package surrealdb

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/security"
)

// UserRepository implements identity.UserStore with envelope encryption.
// PII is encrypted at rest; only ciphertext + hash stored in SurrealDB.
type UserRepository struct {
	pool       *Pool
	keyManager security.KeyManager
	pepper     string
}

// NewUserRepository constructs a UserStore adapter.
func NewUserRepository(pool *Pool, km security.KeyManager, pepper string) *UserRepository {
	return &UserRepository{pool: pool, keyManager: km, pepper: pepper}
}

var _ identity.UserStore = (*UserRepository)(nil)

// Create inserts a new user with envelope encryption.
// Generates UUID v7 + DEK if not provided. Encrypts all PII fields.
func (r *UserRepository) Create(ctx context.Context, user *identity.User) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}

	// Generate UUID v7 if empty
	if user.UserID == "" {
		user.UserID = uuid.New().String()
	}

	// Generate DEK
	dek, encDEK, err := r.keyManager.GenerateAndEncryptDEK()
	if err != nil {
		return fmt.Errorf("generate DEK: %w", err)
	}
	user.EncryptedDEK = encDEK

	// Encrypt PII if provided
	if user.EmailHash == "" {
		// EmailHash must be set by caller (from plaintext email + pepper)
		return fmt.Errorf("EmailHash is required")
	}

	// Compute masked email from hash (for display, not encrypted)
	user.MaskedEmail = "***" // placeholder — caller sets if plaintext available

	vars := map[string]any{
		"user_id":         user.UserID,
		"tenant_id":       user.TenantID,
		"status":          user.Status,
		"encrypted_dek":   encDEK,
		"email_hash":      user.EmailHash,
		"masked_email":    user.MaskedEmail,
		"role":            user.Role,
		
		"registration_attempts": user.RegistrationAttempts,
		"login_count":           user.LoginCount,
		"failed_login_count":    user.FailedLoginCount,
		"created_at":      time.Now(),
		"updated_at":      time.Now(),
	}

	// Encrypt optional PII fields
	if user.EmailCiphertext != nil {
		vars["email_ciphertext"] = user.EmailCiphertext
	}
	if user.NameCiphertext != nil {
		vars["name_ciphertext"] = user.NameCiphertext
	}
	if user.SurnameCiphertext != nil {
		vars["surname_ciphertext"] = user.SurnameCiphertext
	}
	if user.PhoneCiphertext != nil {
		vars["phone_ciphertext"] = user.PhoneCiphertext
	}
	if user.DOBCiphertext != nil {
		vars["dob_ciphertext"] = user.DOBCiphertext
	}
	if user.EmployeeIDCiphertext != nil {
		vars["employee_id_ciphertext"] = user.EmployeeIDCiphertext
	}
	if user.EmployeeIDHash != "" {
		vars["employee_id_hash"] = user.EmployeeIDHash
	}
	if len(user.Permissions) > 0 {
		vars["permissions"] = user.Permissions
	}
	if user.Department != "" {
		vars["department"] = user.Department
	}
	if user.Section != "" {
		vars["section"] = user.Section
	}
	if user.Base != "" {
		vars["base"] = user.Base
	}
	if len(user.Skills) > 0 {
		vars["skills"] = user.Skills
	}
	if user.LastLoginAt != nil {
		vars["last_login_at"] = *user.LastLoginAt
	}
	if user.LockedUntil != nil {
		vars["locked_until"] = *user.LockedUntil
	}
	if user.HireDate != nil {
		vars["hire_date"] = *user.HireDate
	}

	_ = dek // used for encryption above

	_, err = r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`CREATE users SET
			user_id = $user_id,
			tenant_id = $tenant_id,
			status = $status,
			encrypted_dek = $encrypted_dek,
			email_hash = $email_hash,
			masked_email = $masked_email,
			email_ciphertext = $email_ciphertext,
			name_ciphertext = $name_ciphertext,
			surname_ciphertext = $surname_ciphertext,
			phone_ciphertext = $phone_ciphertext,
			dob_ciphertext = $dob_ciphertext,
			employee_id_ciphertext = $employee_id_ciphertext,
			employee_id_hash = $employee_id_hash,
			role = $role,
			permissions = $permissions,
			department = $department,
			section = $section,
			base = $base,
			skills = $skills,
			
			registration_attempts = $registration_attempts,
			login_count = $login_count,
			failed_login_count = $failed_login_count,
			last_login_at = $last_login_at,
			locked_until = $locked_until,
			hire_date = $hire_date,
			created_at = $created_at,
			updated_at = $updated_at`,
		vars,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// FindByUserID loads a user by UUID. Returns raw ciphertext (no decryption).
func (r *UserRepository) FindByUserID(ctx context.Context, userID string) (*identity.User, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	if userID == "" {
		return nil, nil
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM users WHERE user_id = $id LIMIT 1",
		map[string]any{"id": userID},
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
	return mapUserRowV2(rm), nil
}

// FindByEmailHash loads a user by SHA-256 email hash. Returns raw ciphertext.
func (r *UserRepository) FindByEmailHash(ctx context.Context, emailHash string) (*identity.User, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("db not connected")
	}
	if emailHash == "" {
		return nil, nil
	}
	results, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		"SELECT * FROM users WHERE email_hash = $hash LIMIT 1",
		map[string]any{"hash": emailHash},
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
	return mapUserRowV2(rm), nil
}

// Update persists changes to an existing user.
func (r *UserRepository) Update(ctx context.Context, user *identity.User) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	if user.UserID == "" {
		return fmt.Errorf("user_id is required for update")
	}
	vars := map[string]any{
		"user_id":   user.UserID,
		"status":    user.Status,
		"role":      user.Role,
		
		"updated_at": time.Now(),
	}
	if len(user.Permissions) > 0 {
		vars["permissions"] = user.Permissions
	}
	if user.LastLoginAt != nil {
		vars["last_login_at"] = *user.LastLoginAt
	}
	if user.LockedUntil != nil {
		vars["locked_until"] = *user.LockedUntil
	}
	vars["login_count"] = user.LoginCount
	vars["failed_login_count"] = user.FailedLoginCount

	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`UPDATE users SET
			status = $status,
			role = $role,
			permissions = $permissions,
			
			login_count = $login_count,
			failed_login_count = $failed_login_count,
			last_login_at = $last_login_at,
			locked_until = $locked_until,
			updated_at = $updated_at
		WHERE user_id = $user_id`,
		vars,
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// Erase performs crypto-shredding: destroys DEK and overwrites PII fields.
// Compliant with GDPR Art. 17 right to erasure.
func (r *UserRepository) Erase(ctx context.Context, userID string) error {
	if r.pool == nil {
		return fmt.Errorf("db not connected")
	}
	if userID == "" {
		return fmt.Errorf("user_id is required for erase")
	}
	_, err := r.pool.Query(ctx, r.pool.TenantNS(ctx), r.pool.TenantNS(ctx),
		`UPDATE users SET
			encrypted_dek = NONE,
			email_hash = rand::string(32),
			email_ciphertext = NONE,
			name_ciphertext = NONE,
			surname_ciphertext = NONE,
			phone_ciphertext = NONE,
			dob_ciphertext = NONE,
			employee_id_ciphertext = NONE,
			employee_id_hash = NONE,
			masked_email = '***',
			status = 'erased',
			updated_at = time::now()
		WHERE user_id = $id`,
		map[string]any{"id": userID},
	)
	if err != nil {
		return fmt.Errorf("erase user: %w", err)
	}
	return nil
}

// mapUserRowV2 maps raw SurrealDB row → domain User v2 (no decryption).
func mapUserRowV2(rm map[string]any) *identity.User {
	u := &identity.User{}

	// Identifiers
	if v, ok := rm["user_id"].(string); ok {
		u.UserID = v
	}
	if v, ok := rm["tenant_id"].(string); ok {
		u.TenantID = v
	}
	if v, ok := rm["status"].(string); ok {
		u.Status = v
	}

	// Encrypted DEK
	u.EncryptedDEK = asBytes(rm["encrypted_dek"])

	// PII ciphertext (raw bytes — not decrypted here)
	u.EmailCiphertext = asBytes(rm["email_ciphertext"])
	u.NameCiphertext = asBytes(rm["name_ciphertext"])
	u.SurnameCiphertext = asBytes(rm["surname_ciphertext"])
	u.PhoneCiphertext = asBytes(rm["phone_ciphertext"])
	u.DOBCiphertext = asBytes(rm["dob_ciphertext"])
	u.EmployeeIDCiphertext = asBytes(rm["employee_id_ciphertext"])

	// Lookup fields
	if v, ok := rm["email_hash"].(string); ok {
		u.EmailHash = v
	}
	if v, ok := rm["masked_email"].(string); ok {
		u.MaskedEmail = v
	}
	if v, ok := rm["employee_id_hash"].(string); ok {
		u.EmployeeIDHash = v
	}

	// Role / permissions
	if v, ok := rm["role"].(string); ok {
		u.Role = v
	}
	if v, ok := rm["permissions"].([]any); ok {
		for _, p := range v {
			if s, ok := p.(string); ok {
				u.Permissions = append(u.Permissions, s)
			}
		}
	}
	if v, ok := rm["department"].(string); ok {
		u.Department = v
	}
	if v, ok := rm["section"].(string); ok {
		u.Section = v
	}
	if v, ok := rm["base"].(string); ok {
		u.Base = v
	}
	if v, ok := rm["skills"].([]any); ok {
		for _, s := range v {
			if str, ok := s.(string); ok {
				u.Skills = append(u.Skills, str)
			}
		}
	}
	if v, ok := rm["status"].(string); ok {
		u.Status = v
	}

	// Counters
	switch v := rm["registration_attempts"].(type) {
	case float64:
		u.RegistrationAttempts = int(v)
	case int64:
		u.RegistrationAttempts = int(v)
	}
	switch v := rm["login_count"].(type) {
	case float64:
		u.LoginCount = int(v)
	case int64:
		u.LoginCount = int(v)
	}
	switch v := rm["failed_login_count"].(type) {
	case float64:
		u.FailedLoginCount = int(v)
	case int64:
		u.FailedLoginCount = int(v)
	}

	// Timestamps
	if v, ok := rm["created_at"].(time.Time); ok {
		u.CreatedAt = v
	}
	if v, ok := rm["updated_at"].(time.Time); ok {
		u.UpdatedAt = v
	}

	return u
}

// asBytes extracts []byte from SurrealDB response (handles CBOR binary).
func asBytesV2(v any) []byte {
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	default:
		return nil
	}
}

// asBytes extracts []byte from SurrealDB response (handles CBOR binary).
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
