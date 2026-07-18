package surrealdb_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/loxtu/loxtu-go/internal/adapters/persistence/surrealdb"
	"github.com/loxtu/loxtu-go/internal/config"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/security"
)

func setupRepo(t *testing.T) (*surrealdb.UserRepository, *surrealdb.Pool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.SurrealDBFromEnv()
	pool, err := surrealdb.NewPool(ctx, surrealdb.Config{
		Endpoint: cfg.Endpoint, Username: cfg.Username, Password: cfg.Password,
		Namespace: cfg.Namespace, Database: cfg.Database, MaxConns: cfg.MaxConns,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	km, err := security.NewEnvKeyManager()
	if err != nil {
		pool.Close()
		t.Fatalf("NewEnvKeyManager: %v", err)
	}

	pepper := osGetenv("LOXTU_HASH_PEPPER", "")
	repo := surrealdb.NewUserRepository(pool, km, pepper)
	return repo, pool, pepper
}

func osGetenv(key, fb string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fb
}

func TestUserRepo_Create_EncryptsPII(t *testing.T) {
	repo, pool, pepper := setupRepo(t)
	defer pool.Close()

	ctx := context.Background()
	email := "shredding-test@loxtu.com"
	emailHash := security.HashEmail(email, pepper)
	dek, _ := security.GenerateDEK()
	emailCipher, _ := security.EncryptPII(email, dek)

	user := &identity.User{
		EmailHash:       emailHash,
		TenantID:        "loxtu",
		Status:          "pending",
		EmailCiphertext: emailCipher,
		MaskedEmail:     security.MaskEmail(email),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if user.UserID == "" {
		t.Fatal("UserID should be generated")
	}
	if len(user.EncryptedDEK) == 0 {
		t.Fatal("EncryptedDEK should be set")
	}

	// Verify via FindByEmailHash
	found, err := repo.FindByEmailHash(ctx, emailHash)
	if err != nil {
		t.Fatalf("FindByEmailHash: %v", err)
	}
	if found == nil {
		t.Fatal("user should exist after Create")
	}
	if found.UserID != user.UserID {
		t.Errorf("UserID mismatch: %s != %s", found.UserID, user.UserID)
	}
	if len(found.EncryptedDEK) == 0 {
		t.Error("EncryptedDEK should be stored")
	}
	if len(found.EmailCiphertext) == 0 {
		t.Error("EmailCiphertext should be stored")
	}

	t.Logf("✅ Created: UserID=%s, EncryptedDEK=%d bytes, EmailCiphertext=%d bytes",
		user.UserID, len(user.EncryptedDEK), len(user.EmailCiphertext))
}

func TestUserRepo_Erase_WipesData(t *testing.T) {
	repo, pool, pepper := setupRepo(t)
	defer pool.Close()

	ctx := context.Background()
	email := "erase-test@loxtu.com"
	emailHash := security.HashEmail(email, pepper)
	dek, _ := security.GenerateDEK()
	emailCipher, _ := security.EncryptPII(email, dek)

	// Step 1: Create
	user := &identity.User{
		EmailHash:       emailHash,
		TenantID:        "loxtu",
		Status:          "active",
		EmailCiphertext: emailCipher,
		MaskedEmail:     security.MaskEmail(email),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Logf("Created: %s", user.UserID)

	// Step 2: Erase
	if err := repo.Erase(ctx, user.UserID); err != nil {
		t.Fatalf("Erase: %v", err)
	}

	// Step 3: Verify user still exists but data is wiped
	found, err := repo.FindByUserID(ctx, user.UserID)
	if err != nil {
		t.Fatalf("FindByUserID after Erase: %v", err)
	}
	if found == nil {
		t.Fatal("user should still exist after Erase")
	}

	// encrypted_dek should be nil
	if len(found.EncryptedDEK) != 0 {
		t.Errorf("EncryptedDEK should be empty, got %d bytes", len(found.EncryptedDEK))
	}

	// email_ciphertext should be nil
	if len(found.EmailCiphertext) != 0 {
		t.Errorf("EmailCiphertext should be empty, got %d bytes", len(found.EmailCiphertext))
	}

	// status should be "erased"
	if found.Status != "erased" {
		t.Errorf("Status = %q, want %q", found.Status, "erased")
	}

	// masked_email should be wiped
	if found.MaskedEmail != "***" {
		t.Errorf("MaskedEmail = %q, want %q", found.MaskedEmail, "***")
	}

	// email_hash should be random (not original)
	if found.EmailHash == emailHash {
		t.Error("EmailHash should be overwritten with random string")
	}

	// Step 4: DecryptPII on empty/nil data — should fail
	_, err = security.DecryptPII(nil, dek)
	if err == nil {
		t.Error("DecryptPII(nil) should return error")
	}
	_, err = security.DecryptPII([]byte{}, dek)
	if err == nil {
		t.Error("DecryptPII(empty) should return error")
	}
	_, err = security.DecryptPII([]byte{1, 2, 3}, dek)
	if err == nil {
		t.Error("DecryptPII(garbage) should return error")
	}

	t.Log("✅ Crypto-shredding verified: DEK=NONE, PII=NONE, status=erased, hash=random")
}
