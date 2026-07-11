# Failure modes: auth (sessions + magic-link)

`failure -> detection -> recovery`. Detection cites the slog event / user surface; a blank recovery cell is a gap.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Magic-link SMTP handoff fails | `slog.Error("magic link email failed")` (`web_auth.go:89`) - but user still sees "check your email" (operator-only signal) | User re-requests (rate-limited); no send-retry |
| Magic-link token expired | `ErrExpired` in atomic consume (`auth_magiclink.go:217`) -> "That link has expired" | Re-request link |
| Magic-link token replayed / used | Atomic `UPDATE ... consumed_at IS NULL RETURNING` -> loser gets "invalid or already used" (`web_auth.go:108`) | Re-request; single-winner guaranteed |
| Session fixation | Structurally prevented: fresh token only minted at `startSession`; no anonymous session adopted (`auth_sessions.go:38`) | N/A |
| Stolen session cookie replayed | Bounded by 4h rotation (`auth_sessions.go:29`); stale hash -> anonymous | Rotation automatic; logout deletes |
| DB down during login | `slog.Error("password verify failed")` / `"magic link create failed"` + HTTP 500 (`web_auth.go:55`) | User retries when DB returns; not queued |

## Gaps

- **Mailer disabled (empty `SMTPHost`) drops the link but returns success.** Only `slog.Warn("mailer disabled ... dropping message")`, returns `nil` (`mailer.go:42`); caller sees success, user sees "check your email". No error surfaced.
- **No mail delivery / bounce tracking.** SMTP handoff success is treated as delivery; a bounced/greylisted/spam link is silent (`mailer.go`).
- **Magic-link replay attempt logs nothing security-relevant** - generic user message only, no `slog.Warn`/audit event (`auth_magiclink.go:213`).
- **No stolen-session anomaly detection** (concurrent-use / IP-change) (`auth_sessions.go`).
- **DB failure at session-create gives a misleading success-redirect.** `startSession` returns void; on `CreateSession` failure the handler still redirects to `/devices` with no cookie, then `RequireAuth` bounces to `/login` - no user-facing error (`web_auth.go:59`, `:145`).
- **Password-reset is not atomic (non-transactional multi-step class).** `ConsumeResetLink` -> `SetPassword` (tx) -> `MarkResetConsumed` (separate tx, failure only `slog.Warn`). A crash between steps leaves the reset token consumable for its remaining TTL after the password already changed (`web_auth.go:307`).

---

Related: [`oauth.md`](oauth.md), [`../security-review-checklist.md`](../security-review-checklist.md), [`../operator-role.md`](../operator-role.md).
