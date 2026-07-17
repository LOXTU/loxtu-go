// Package config loads process configuration from the environment for the composition root.
// Adapters receive pure Config structs — they never read ENV themselves.
package config

import (
	"os"
	"strconv"
	"time"

	"github.com/loxtu/loxtu-go/internal/adapters/messaging/smtp"
	"github.com/loxtu/loxtu-go/internal/adapters/persistence/surrealdb"
)

// SurrealDBFromEnv builds surrealdb.Config from SURREALDB_* variables.
func SurrealDBFromEnv() surrealdb.Config {
	return surrealdb.Config{
		Endpoint:  envOr("SURREALDB_ENDPOINT", "ws://surrealdb:8881/rpc"),
		Username:  envOr("SURREALDB_USER", "root"),
		Password:  envOr("SURREALDB_PASS", "root"),
		Namespace: envOr("SURREALDB_NS", "loxtu"),
		Database:  envOr("SURREALDB_DB", "loxtu"),
		MaxConns:  envInt("SURREALDB_POOL_SIZE", 10),
	}
}

// SMTPFromEnv builds smtp.Config from SMTP_* variables.
func SMTPFromEnv() smtp.Config {
	return smtp.Config{
		Host:          envOr("SMTP_HOST", "stalwart"),
		Port:          envInt("SMTP_PORT", 465),
		User:          envOr("SMTP_USER", "noreply@loxtu.com"),
		Password:      envOr("SMTP_PASSWORD", ""),
		FromAddr:      envOr("SMTP_FROM", "noreply@loxtu.com"),
		FromName:      envOr("SMTP_FROM_NAME", "LOXTU"),
		Enabled:       envOr("SMTP_ENABLED", "false") == "true",
		Timeout:       10 * time.Second,
		TLSServerName: envOr("SMTP_TLS_SERVERNAME", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
