# Failure modes: OAuth / OIDC

`failure -> detection -> recovery`. State / PKCE / nonce are single-use and DB-atomic; the one cross-step seam is O10. A blank recovery cell is a gap.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Provider/IdP down (discovery fails) | `slog.Error("oidc provider load failed")` + HTTP 502 (`web/oauth.go:49`, `:111`) | Manual retry when IdP returns; no cached-provider fallback (discovery per request) |
| Misconfigured redirect URI | Often none app-side (IdP refuses); if IdP redirects with `?error=` -> "Sign-in cancelled by identity provider" (`web/oauth.go:83`) | Operator fixes `oauth_providers` / IdP client |
| Token validation failure (sig/aud/iss) | `verifier.Verify` error -> `slog.Error("oidc exchange failed")` (`oauth.go:208`) | Retry |
| Nonce mismatch (replay/CSRF) | `"oauth: nonce mismatch"` -> same exchange-failed path (`oauth.go:212`) | Retry (fresh nonce per Start) |
| PKCE verifier mismatch | IdP rejects exchange -> "oidc exchange failed" (`oauth.go:198`); S256 enforced every flow | Retry (fresh verifier) |
| State unknown / expired / replayed | Single-use `DELETE ... RETURNING` + expiry recheck -> `slog.Warn("oidc state unknown")` -> "link expired, try again" (`oauth.go:174`) | Retry; state atomically single-use |
| Identity already linked to another user | Unique-violation -> `ErrConflict` -> `/settings?err=identity_taken` (`service/oauth.go:284`) | User-visible; no auto-merge |
| Sign-in ok but no local account | "No Thesada account matches..." (no auto-provision) (`web/oauth.go:176`) | Sign in locally, then link from settings |

## Gaps

- **Auto-link then session-create is not one transaction (non-transactional multi-step class).** On email-match, identity is `LinkIdentity`'d, then `startSession` (`web/oauth.go:162`); a `CreateSession` DB failure leaves the identity linked with no session and no user error (only the operator `session create failed` log). Next login recovers, but the partial state is invisible.
- **No cached-provider fallback:** OIDC discovery runs per request via `LoadProvider`, so a brief IdP blip fails the whole flow with a 502 rather than using a last-known-good provider.

---

Related: [`auth.md`](auth.md), [`../security-review-checklist.md`](../security-review-checklist.md).
