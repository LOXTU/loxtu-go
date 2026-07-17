package identity

import (
	"context"
	"time"
)

// Notification is the base payload for out-of-band delivery.
// Channel adapters (SMTP, SMS, push, cabin) map RecipientID as needed.
//
// Design: family of interfaces (OTPSender, AlertSender), not one mega-sender.
// Expansion path: PushSender, SMSSender, CabinDisplaySender as separate ports.
// Implementations live under adapters/messaging/* and adapters/security/*.
type Notification struct {
	// RecipientID is email, user id, phone, or device token (channel-specific).
	RecipientID string
	// Metadata holds optional channel hints (e.g. locale, template).
	Metadata map[string]string
}

// OTPNotification is a one-time passcode message.
type OTPNotification struct {
	Notification
	Code   string
	Expiry time.Duration
}

// AlertNotification is a human-readable operational alert.
type AlertNotification struct {
	Notification
	Title string
	Body  string
	Data  map[string]string
}

// OTPSender delivers one-time codes (email/SMS family).
// Implemented by adapters/messaging/smtp (and future SMS).
type OTPSender interface {
	SendOTP(ctx context.Context, notif OTPNotification) error
}

// AlertSender delivers push / on-screen / cabin-display alerts.
// Implemented later by Web Push, Telegram, cabin adapters.
type AlertSender interface {
	SendAlert(ctx context.Context, notif AlertNotification) error
}
