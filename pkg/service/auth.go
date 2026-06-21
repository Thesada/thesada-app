// AuthService and the shared auth types. The service is split across
// several files in this package by concern:
//
//	auth.go           - AuthService struct, User type, shared errors, helpers
//	auth_users.go     - users table: lookup, create, update, password
//	auth_sessions.go  - user_sessions: create, validate, rotate, impersonate
//	auth_magiclink.go - magic_link_tokens: login + reset link issue/consume
//	auth_waitlist.go  - waitlist: list, count, convert, add, delete
package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// AuthService handles users, user_sessions, magic_link_tokens, and waitlist.
type AuthService struct {
	cfg   *config.Config
	pools db.Pools
}

// User is the exported shape of the users table for consumers outside the
// service package (web handlers, middleware). Password hash is intentionally
// not exported here to avoid leaking it across layers.
type User struct {
	ID             uuid.UUID
	TenantID       string
	Email          string
	DisplayName    *string
	TelegramChatID *string
	IsAdmin        bool
	IsSuperAdmin   bool
	CreatedAt      time.Time
	LastLoginAt    *time.Time
}

// ErrNotFound means the lookup succeeded but returned zero rows.
var ErrNotFound = errors.New("not found")

// ErrBadCredentials means the email or password did not match.
var ErrBadCredentials = errors.New("bad credentials")

// ErrExpired means a magic link or session has expired.
var ErrExpired = errors.New("expired")

// randomToken returns a url-safe base64 string containing n random bytes.
// in: number of raw random bytes. out: encoded string, error from crypto/rand.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
