// Package audit holds security and GDPR consent event entities and helpers.
package audit

// SecurityEvent is written to security_audit (NIS2/SOC2 trail).
type SecurityEvent struct {
	ActorID          string `json:"actor_id"`
	ActorEmailMasked string `json:"actor_email_masked"`
	Action           string `json:"action"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	Status           string `json:"status"`
	ClientIP         string `json:"client_ip"`
	ReqID            string `json:"reqid"`
}

// ConsentEvent is written to user_consents (GDPR).
type ConsentEvent struct {
	ActorID          string `json:"actor_id"`
	ActorEmailMasked string `json:"actor_email_masked"`
	PrivacyPolicy    string `json:"privacy_policy"`
	TermsOfService   string `json:"terms_of_service"`
	ConsentTypes     string `json:"consent_types"`
	ClientIP         string `json:"client_ip"`
	ReqID            string `json:"reqid"`
}

// IsCritical classifies events for LogPublisher.
func (e SecurityEvent) IsCritical() bool {
	switch e.Action {
	case "auth.login.fail", "auth.tenant_mismatch", "session.revoke_all", "passkey.fail":
		return true
	}
	return e.Status == "failure" || e.Status == "denied"
}
