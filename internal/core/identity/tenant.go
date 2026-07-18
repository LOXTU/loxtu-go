package identity

import "time"

// Tenant represents a tenant (airline/airport) in the system.
type Tenant struct {
	TenantID         string
	Name             string
	Type             string // airport, airline, handler
	DomainWhitelist  []string
	Features         []string        // ["roster", "turnaround", "gant"]
	SecurityPolicy   SecurityPolicy
	Quotas           Quotas
	CreatedAt        time.Time
}

// SecurityPolicy defines tenant-level security requirements.
type SecurityPolicy struct {
	MFARequired               bool
	PinEnabled                bool
	AccessTokenTimeoutMinutes  int
	RefreshTokenTimeoutMinutes int
}

// Quotas defines tenant-level resource limits.
type Quotas struct {
	MaxUsers int
}

// DefaultSecurityPolicy returns sensible defaults.
func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		MFARequired:               false,
		PinEnabled:                false,
		AccessTokenTimeoutMinutes:  15,
		RefreshTokenTimeoutMinutes: 43200, // 30 days
	}
}

// DefaultQuotas returns sensible defaults.
func DefaultQuotas() Quotas {
	return Quotas{MaxUsers: 1000}
}
