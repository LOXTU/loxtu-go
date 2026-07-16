// Package email provides SMTP email sending via Stalwart or dev fallback.
package email

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// ── Config ─────────────────────────────────────────────────────────────────

// Config holds SMTP connection settings.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      string
	FromAddr      string
	FromName      string
	Enabled       bool
	Timeout       time.Duration
	TLSServerName string // optional, for cert validation if different from Host
}

// DefaultConfig reads config from environment variables.
func DefaultConfig() Config {
	return Config{
		Host:          envOr("SMTP_HOST", "stalwart"),
		Port:          envOrInt("SMTP_PORT", 465),
		User:          envOr("SMTP_USER", "noreply@loxtu.com"),
		Password:      envOr("SMTP_PASSWORD", ""),
		FromAddr:      envOr("SMTP_FROM", "noreply@loxtu.com"),
		FromName:      envOr("SMTP_FROM_NAME", "LOXTU"),
		Enabled:       envOr("SMTP_ENABLED", "false") == "true",
		Timeout:       10 * time.Second,
		TLSServerName: envOr("SMTP_TLS_SERVERNAME", ""),
	}
}

// ── Client ─────────────────────────────────────────────────────────────────

// Client sends emails via SMTP.
type Client struct {
	config Config
}

// New creates a new email client with the given config.
func New(config Config) *Client {
	return &Client{config: config}
}

// SendOTP sends a one-time passcode via email.
// If SMTP is disabled, logs the code to stdout (dev fallback).
func (c *Client) SendOTP(to, code string) error {
	if !c.config.Enabled {
		log.Printf("[DEV MODE] OTP for %s: %s", to, code)
		return nil
	}

	subject := "Your LOXTU verification code"
	body := GenerateOTPEmail(code)
	msg := buildMessage(c.config.FromAddr, to, subject, body)

	addr := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))

	// TLS dial (implicit TLS — works for port 465)
	tlsServerName := c.config.TLSServerName
	if tlsServerName == "" {
		tlsServerName = c.config.Host
	}
	tlsCfg := &tls.Config{
		ServerName:         tlsServerName,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: c.config.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial SMTP: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.config.Host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer client.Close()

	// Auth
	if c.config.User != "" && c.config.Password != "" {
		auth := smtp.PlainAuth("", c.config.User, c.config.Password, c.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}

	// Mail from
	if err := client.Mail(c.config.FromAddr); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}

	// Rcpt to
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	// Data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}

	// Mask email for logging
	masked := maskEmail(to)
	log.Printf("[email] OTP sent to %s", masked)
	return nil
}

// ── Helpers ────────────────────────────────────────────────────────────────

func buildMessage(from, to, subject, body string) string {
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n",
		from, to, subject)
	return headers + body
}

func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 2 {
		return local[:1] + "***@" + parts[1]
	}
	return local[:1] + "***" + local[len(local)-1:] + "@" + parts[1]
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}