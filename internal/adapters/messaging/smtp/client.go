// Package smtp implements identity.OTPSender via Stalwart SMTP.
// Accepts pure Config only — composition root (main/config) loads ENV.
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"

	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/shared/httputil"
)

// Config holds SMTP connection settings (injected by main).
type Config struct {
	Host          string
	Port          int
	User          string
	Password      string
	FromAddr      string
	FromName      string
	Enabled       bool
	Timeout       time.Duration
	TLSServerName string
}

// Client sends emails via SMTP.
type Client struct {
	config Config
}

// New creates an OTPSender from injected Config.
func New(config Config) *Client {
	return &Client{config: config}
}

var _ identity.OTPSender = (*Client)(nil)

// SendOTP delivers a one-time passcode from OTPNotification.
func (c *Client) SendOTP(ctx context.Context, notif identity.OTPNotification) error {
	to := notif.RecipientID
	code := notif.Code
	if to == "" || code == "" {
		return fmt.Errorf("OTP notification missing RecipientID or Code")
	}
	if !c.config.Enabled {
		log.Printf("[DEV MODE] OTP for %s: %s", httputil.MaskEmail(to), code)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	subject := "Your LOXTU verification code"
	body := GenerateOTPEmail(code)
	msg := buildMessage(c.config.FromAddr, to, subject, body)
	addr := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))

	tlsServerName := c.config.TLSServerName
	if tlsServerName == "" {
		tlsServerName = c.config.Host
	}
	tlsCfg := &tls.Config{
		ServerName: tlsServerName,
		MinVersion: tls.VersionTLS12,
	}

	timeout := c.config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < timeout {
			timeout = rem
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
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

	if c.config.User != "" && c.config.Password != "" {
		auth := smtp.PlainAuth("", c.config.User, c.config.Password, c.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	if err := client.Mail(c.config.FromAddr); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
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

	log.Printf("[email] OTP sent to %s", httputil.MaskEmail(to))
	return nil
}

func buildMessage(from, to, subject, body string) string {
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n",
		from, to, subject)
	return headers + body
}
