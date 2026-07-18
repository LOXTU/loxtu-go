// Package telegram implements audit.LogPublisher (noop until credentials configured).
package telegram

import (
	"context"
	"log"

	"github.com/loxtu/loxtu-go/internal/core/audit"
)

// Bot is a no-op LogPublisher when Enabled=false.
type Bot struct {
	Enabled bool
}

// New constructs a LogPublisher (disabled by default).
func New() *Bot { return &Bot{} }

var _ audit.LogPublisher = (*Bot)(nil)

// Publish logs critical events locally when bot is not configured.
func (b *Bot) Publish(ctx context.Context, event audit.SecurityEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !b.Enabled {
		log.Printf("[telegram] (noop) %s %s user=%s", event.Action, event.Status, event.MaskedEmail)
		return nil
	}
	return nil
}
