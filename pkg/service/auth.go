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
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/ratelimit"
)

// AuthService handles users, user_sessions, magic_link_tokens, and waitlist.
type AuthService struct {
	cfg   *config.Config
	pools db.Pools

	loginEmailLimits *ratelimit.Limiter
	loginIPLimits    *ratelimit.Limiter
}

// Per IP is looser than per email so a shared NAT does not lock out an office.
const (
	loginWindow      = 15 * time.Minute
	loginMaxPerEmail = 10
	loginMaxPerIP    = 30
)

// maxLoginCandidates caps bcrypt checks for a reused email (CPU amplification);
// the query orders by created_at so the oldest account wins deterministically.
const maxLoginCandidates = 5

// NewAuthService builds the service and its rate-limit sweepers (context.Background: process lifetime).
// in: cfg, db pools. out: ready *AuthService.
func NewAuthService(cfg *config.Config, pools db.Pools) *AuthService {
	s := &AuthService{
		cfg:              cfg,
		pools:            pools,
		loginEmailLimits: ratelimit.New(loginWindow, loginMaxPerEmail),
		loginIPLimits:    ratelimit.New(loginWindow, loginMaxPerIP),
	}
	s.loginEmailLimits.StartSweeper(context.Background())
	s.loginIPLimits.StartSweeper(context.Background())
	return s
}

// allowLogin records a login attempt and reports whether it is under both rate caps.
// Keyed independently of account existence so throttling leaks no enumeration.
// in: email, source ip. out: true if the attempt may proceed.
func (s *AuthService) allowLogin(email, ip string) bool {
	// Evaluate both buckets (no short-circuit) so an email-throttled attempt
	// still spends its IP token - otherwise spraying one email is free on the IP.
	emailOK := s.loginEmailLimits.Allow("login-email:" + strings.ToLower(email))
	ipOK := ip == "" || s.loginIPLimits.Allow("login-ip:"+ip)
	return emailOK && ipOK
}

// User is the exported shape of the users table; password hash intentionally omitted to prevent cross-layer leaks.
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

// ErrLoginRateLimited means a login exceeded the per-email or per-IP cap (429, not 401).
var ErrLoginRateLimited = errors.New("login rate limited")

// ErrPasswordTooShort means SetPassword got a password under MinPasswordLen.
var ErrPasswordTooShort = errors.New("password too short")

// ErrNotSuperAdmin means a super-admin-only operation ran on a non-super session.
var ErrNotSuperAdmin = errors.New("not a super-admin")

// MinPasswordLen is the minimum stored-password length, enforced in SetPassword.
const MinPasswordLen = 10

// randomToken returns a url-safe base64 string containing n random bytes.
// in: number of raw random bytes. out: encoded string, error from crypto/rand.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
