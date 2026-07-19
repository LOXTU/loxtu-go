package identity_test

import (
	"context"

	"github.com/loxtu/loxtu-go/internal/core/identity"
)

// ── Mock stores (shared across test files in identity_test package) ─────

type mockUserStore struct {
	users map[string]*identity.User
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]*identity.User)}
}

func (m *mockUserStore) Create(_ context.Context, u *identity.User) error {
	m.users[u.UserID] = u
	return nil
}
func (m *mockUserStore) FindByUserID(_ context.Context, userID string) (*identity.User, error) {
	return m.users[userID], nil
}
func (m *mockUserStore) FindByEmailHash(_ context.Context, hash string) (*identity.User, error) {
	for _, u := range m.users {
		if u.EmailHash == hash {
			return u, nil
		}
	}
	return nil, nil
}
func (m *mockUserStore) FindByUserIDHash(_ context.Context, hash string) (*identity.User, error) {
	for _, u := range m.users {
		if u.UserIDHash == hash {
			return u, nil
		}
	}
	return nil, nil
}
func (m *mockUserStore) Update(_ context.Context, u *identity.User) error {
	m.users[u.UserID] = u
	return nil
}
func (m *mockUserStore) Erase(_ context.Context, userID string) error {
	delete(m.users, userID)
	return nil
}

type mockCredStore struct {
	usersByHandle map[string]*identity.PasskeyUser
	credsByKID    map[string]*identity.PasskeyCredential
	credsByUser   map[string][]*identity.PasskeyCredential
}

func newMockCredStore() *mockCredStore {
	return &mockCredStore{
		usersByHandle: make(map[string]*identity.PasskeyUser),
		credsByKID:    make(map[string]*identity.PasskeyCredential),
		credsByUser:   make(map[string][]*identity.PasskeyCredential),
	}
}

func (m *mockCredStore) SaveUser(_ context.Context, _ string, _ []byte, _ string) error {
	return nil
}
func (m *mockCredStore) SaveCredential(_ context.Context, cred *identity.PasskeyCredential) error {
	m.credsByKID[string(cred.CredentialID)] = cred
	m.credsByUser[cred.UserID] = append(m.credsByUser[cred.UserID], cred)
	return nil
}
func (m *mockCredStore) FindCredentialsByUserID(_ context.Context, userID string) ([]*identity.PasskeyCredential, error) {
	return m.credsByUser[userID], nil
}
func (m *mockCredStore) FindCredentialByKID(_ context.Context, kid []byte) (*identity.PasskeyCredential, error) {
	return m.credsByKID[string(kid)], nil
}
func (m *mockCredStore) FindUserByHandle(_ context.Context, handle []byte) (*identity.PasskeyUser, error) {
	return m.usersByHandle[string(handle)], nil
}
func (m *mockCredStore) FindHandleByUserID(_ context.Context, userID string) ([]byte, error) {
	if u, ok := m.usersByHandle[userID]; ok {
		return u.Handle, nil
	}
	return nil, nil
}
func (m *mockCredStore) UpdateSignCount(_ context.Context, _ string, _ []byte, _ uint32) error {
	return nil
}

type mockSessionStore struct {
	sessions map[string]*identity.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]*identity.Session)}
}

func (m *mockSessionStore) Create(_ context.Context, s *identity.Session) error {
	m.sessions[s.TokenHash] = s
	return nil
}
func (m *mockSessionStore) FindByTokenHash(_ context.Context, hash string) (*identity.Session, error) {
	return m.sessions[hash], nil
}
func (m *mockSessionStore) RevokeByUserID(_ context.Context, _ string) error { return nil }
func (m *mockSessionStore) RevokeByTokenHash(_ context.Context, hash string) error {
	delete(m.sessions, hash)
	return nil
}
func (m *mockSessionStore) CleanupExpired(_ context.Context) error { return nil }
