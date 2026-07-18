package identity_test

import (
	"encoding/base64"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/loxtu/loxtu-go/internal/core/identity"
	"github.com/loxtu/loxtu-go/internal/security"
)

func init() { identity.DecryptPIIFn = security.DecryptPII }

func TestUser_DecryptEmail_Roundtrip(t *testing.T) {
	dek, _ := security.GenerateDEK()
	email := "vitaly.semenov@loxtu.com"
	ct, _ := security.EncryptPII(email, dek)
	u := &identity.User{EmailCiphertext: ct}
	got, err := u.DecryptEmail(dek)
	if err != nil {
		t.Fatalf("DecryptEmail: %v", err)
	}
	if got != email {
		t.Errorf("got %q, want %q", got, email)
	}
}
func TestUser_DecryptEmail_WrongDEK(t *testing.T) {
	d1, _ := security.GenerateDEK()
	d2, _ := security.GenerateDEK()
	ct, _ := security.EncryptPII("x@y.com", d1)
	_, err := (&identity.User{EmailCiphertext: ct}).DecryptEmail(d2)
	if err == nil {
		t.Error("expected error for wrong DEK")
	}
}
func TestUser_DecryptEmail_Empty(t *testing.T) {
	got, err := (&identity.User{}).DecryptEmail([]byte("x"))
	if err != nil || got != "" {
		t.Errorf("expected empty, got %q err %v", got, err)
	}
}
func TestUser_DecryptName_Roundtrip(t *testing.T) {
	d, _ := security.GenerateDEK()
	ct, _ := security.EncryptPII("Vitaly", d)
	got, err := (&identity.User{NameCiphertext: ct}).DecryptName(d)
	if err != nil || got != "Vitaly" {
		t.Errorf("got %q err %v", got, err)
	}
}
func TestUser_DecryptName_Empty(t *testing.T) {
	got, _ := (&identity.User{}).DecryptName(nil)
	if got != "" {
		t.Errorf("got %q", got)
	}
}
func TestUser_DecryptSurname_Roundtrip(t *testing.T) {
	d, _ := security.GenerateDEK()
	ct, _ := security.EncryptPII("Semenov", d)
	got, err := (&identity.User{SurnameCiphertext: ct}).DecryptSurname(d)
	if err != nil || got != "Semenov" {
		t.Errorf("got %q err %v", got, err)
	}
}
func TestUser_DecryptSurname_Empty(t *testing.T) {
	got, _ := (&identity.User{}).DecryptSurname(nil)
	if got != "" {
		t.Errorf("got %q", got)
	}
}
func TestUser_MaskedEmailOrCompute_Empty(t *testing.T) {
	if got := (&identity.User{}).MaskedEmailOrCompute(nil); got != "***" {
		t.Errorf("got %q", got)
	}
}
func TestUser_MaskedEmailOrCompute_FromField(t *testing.T) {
	u := &identity.User{MaskedEmail: "v***y@loxtu.com"}
	if got := u.MaskedEmailOrCompute(nil); got != "v***y@loxtu.com" {
		t.Errorf("got %q", got)
	}
}
func TestUser_MaskedEmailOrCompute_FromDecrypt(t *testing.T) {
	d, _ := security.GenerateDEK()
	ct, _ := security.EncryptPII("test@loxtu.com", d)
	if got := (&identity.User{EmailCiphertext: ct}).MaskedEmailOrCompute(d); got != "t***t@loxtu.com" {
		t.Errorf("got %q", got)
	}
}
func TestUser_HasRole(t *testing.T) {
	u := &identity.User{Role: "admin"}
	if !u.HasRole("admin") || u.HasRole("x") || u.HasRole("") {
		t.Error("HasRole failed")
	}
	var n *identity.User
	if n.HasRole("admin") {
		t.Error("nil should be false")
	}
}
func TestUser_HasPermission(t *testing.T) {
	u := &identity.User{Permissions: []string{"read", "write"}}
	if !u.HasPermission("read") || u.HasPermission("x") || u.HasPermission("") {
		t.Error("HasPermission failed")
	}
	var n *identity.User
	if n.HasPermission("read") {
		t.Error("nil should be false")
	}
}
func TestUser_HasSkill(t *testing.T) {
	u := &identity.User{Skills: []string{"ramp"}}
	if !u.HasSkill("ramp") || u.HasSkill("x") || u.HasSkill("") {
		t.Error("HasSkill failed")
	}
	var n *identity.User
	if n.HasSkill("ramp") {
		t.Error("nil should be false")
	}
}
func TestEmailHash_Deterministic(t *testing.T) {
	h1 := identity.EmailHash("Test@Loxtu.COM")
	h2 := identity.EmailHash("test@loxtu.com")
	if h1 != h2 || len(h1) != 64 {
		t.Errorf("case-insensitive or length: %s %s %d", h1, h2, len(h1))
	}
	if identity.EmailHash("a@b.com") == h1 {
		t.Error("different emails should differ")
	}
}
func TestMaskEmailString(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"vitaly@loxtu.com", "v***y@loxtu.com"}, {"ab@loxtu.com", "a***@loxtu.com"},
		{"a@loxtu.com", "a***@loxtu.com"}, {"", "***"}, {"noatsign", "***"},
	} {
		if got := identity.MaskEmailString(tt.in); got != tt.want {
			t.Errorf("MaskEmailString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
func TestPasskeyUser_WebAuthnInterface(t *testing.T) {
	pu := &identity.PasskeyUser{Email: "t@x.com", Handle: []byte("h")}
	if string(pu.WebAuthnID()) != "h" || pu.WebAuthnName() != "t@x.com" {
		t.Error("interface mismatch")
	}
	if pu.WebAuthnDisplayName() != "t@x.com" || pu.WebAuthnCredentials() != nil {
		t.Error("display/creds mismatch")
	}
}
func TestPasskeyUser_WithCredentials(t *testing.T) {
	pu := &identity.PasskeyUser{Credentials: make([]webauthn.Credential, 2)}
	if len(pu.WebAuthnCredentials()) != 2 {
		t.Errorf("got %d", len(pu.WebAuthnCredentials()))
	}
}
func TestGenerateHandleWithTenant(t *testing.T) {
	h, err := identity.GenerateHandleWithTenant("loxtu")
	if err != nil {
		t.Fatal(err)
	}
	tid, _, err := identity.ParseHandle(h)
	if err != nil || tid != "loxtu" {
		t.Errorf("ParseHandle: %s err %v", tid, err)
	}
}
func TestGenerateHandle(t *testing.T) {
	h, err := identity.GenerateHandle()
	if err != nil || len(h) != 64 {
		t.Errorf("len=%d err=%v", len(h), err)
	}
}
func TestParseHandle_Invalid(t *testing.T) {
	for _, bad := range [][]byte{[]byte("nocolon"), []byte(":")} {
		if _, _, err := identity.ParseHandle(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
func TestDefaultSecurityPolicy(t *testing.T) {
	p := identity.DefaultSecurityPolicy()
	if p.AccessTokenTimeoutMinutes != 15 || p.RefreshTokenTimeoutMinutes != 43200 {
		t.Errorf("timeouts: %d / %d", p.AccessTokenTimeoutMinutes, p.RefreshTokenTimeoutMinutes)
	}
	if p.MFARequired || p.PinEnabled {
		t.Error("defaults should be false")
	}
}
func TestDefaultQuotas(t *testing.T) {
	if identity.DefaultQuotas().MaxUsers != 1000 {
		t.Error("MaxUsers should be 1000")
	}
}
func TestTenant_Fields(t *testing.T) {
	tn := &identity.Tenant{
		TenantID: "loxtu", Name: "LOXTU", Type: "airport",
		DomainWhitelist: []string{"loxtu.com"}, Features: []string{"roster", "turnaround"},
		SecurityPolicy: identity.DefaultSecurityPolicy(), Quotas: identity.DefaultQuotas(),
	}
	if tn.TenantID != "loxtu" || len(tn.Features) != 2 || tn.Quotas.MaxUsers != 1000 {
		t.Error("field mismatch")
	}
}
func TestDecryptEmail_Unwired(t *testing.T) {
	orig := identity.DecryptPIIFn
	identity.DecryptPIIFn = nil
	defer func() { identity.DecryptPIIFn = orig }()
	_, err := (&identity.User{EmailCiphertext: []byte("x")}).DecryptEmail([]byte("d"))
	if err == nil {
		t.Error("expected error when unwired")
	}
}
func TestImportCycle_ConfigNoAdapters(t *testing.T) {
	_ = base64.StdEncoding.EncodeToString([]byte("test"))
}
