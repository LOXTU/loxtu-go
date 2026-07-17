package audit

import "context"

// Service filters audit events and persists + optionally publishes them.
type Service struct {
	store     Store
	publisher LogPublisher
}

// NewService constructs the audit domain service.
func NewService(store Store, publisher LogPublisher) *Service {
	return &Service{store: store, publisher: publisher}
}

// LogSecurity persists the event; on critical severity also Publish to operators.
func (s *Service) LogSecurity(ctx context.Context, event SecurityEvent) error {
	if s.store != nil {
		if err := s.store.LogSecurityEvent(ctx, event); err != nil {
			return err
		}
	}
	if event.IsCritical() && s.publisher != nil {
		_ = s.publisher.Publish(ctx, event)
	}
	return nil
}
