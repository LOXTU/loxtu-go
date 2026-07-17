package audit

import "context"

// Store persists security audit events. Implemented by adapters (worker pool allowed).
type Store interface {
	LogSecurityEvent(ctx context.Context, event SecurityEvent) error
}

// LogPublisher pushes critical events to operators (Telegram). Optional dependency.
type LogPublisher interface {
	Publish(ctx context.Context, event SecurityEvent) error
}

// Lifecycle is optional Start/Stop for long-running adapter resources (workers).
type Lifecycle interface {
	Start()
	Stop()
}
