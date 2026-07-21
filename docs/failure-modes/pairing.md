# Failure modes: device pairing (app side)

`failure -> detection -> recovery` for the app side of the fw pairing flow (`pkg/web/admin_pair.go`). The firmware side lives in [`thesada-fw/docs/failure-modes/mqtt.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/mqtt.md). A blank recovery cell is a gap.

There is **no app-side bearer pairing token**: pairing is gated by super-admin session auth (404 to hide the surface), and device identity is asserted by MQTT `device_id`. The anti-spoof control is the cross-tenant pairing guard `FindActivePairingTenant` (`pkg/service/certificate.go:237`), which logs + drops on tenant mismatch.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| mTLS provisioning fails mid-flow (cert/config/secret push) | Each step returns `(msg, ok)`; failure -> `slog.Error(...)` + `failPairIssue` flips the cert row `status='failed'`, records the `cert.issue` audit outcome, and surfaces `?error=` FlashErr (`admin_pair.go:333`) | Manual re-click; `IssuePending` supersedes the failed row + idempotent pushes (secret.set overwrites, dynsec "already exists" tolerated) |
| Cert minting fails (`SignDeviceCert`) | `slog.Error("sign device cert failed")` -> `error=sign+failed`; CA not initialized -> `error=CA+not+initialized` (`admin_pair.go:186`) | Fix CA / passphrase, retry |
| Persist of the `pending` row fails (before any push) | `slog.Error("persist pending device cert failed")` -> `error=persist+failed` (`admin_pair.go:209`); nothing was pushed, device untouched | Re-click Issue |
| `Activate` flip fails after all pushes succeed | `slog.Error("activate device cert failed")` -> `error=activate+failed` (`admin_pair.go:294`); row stays `pending`/flips `failed`, device HAS the cert but DB does not count it live | Re-click Issue (supersede re-pushes; firmware tolerates re-set) |
| dynsec role/client create fails | `slog.Error("dynsec create... failed")` (`admin_pair.go:282`) | Retry ("already exists" tolerated) |
| Post-pair `cli/restart` publish lost | `slog.Warn("pair issue: cli/restart publish failed")` (`admin_pair.go:310`) - but pairing already marked done | Best-effort; device keeps old port until manual restart / watchdog |

## Gaps

- **Device-side NVS writes stay non-transactional.** The DB side is now persist-first (`IssuePending` -> push -> `Activate`, `admin_pair.go:161`): every issue attempt leaves a queryable `device_certificates` row (`pending`/`failed`/`active`), so a mid-air failure can no longer produce a certed device the DB never heard of. What remains: a partial NVS write on the device itself (e.g. client_cert stored, client_key push lost) has no device-side rollback - the `failed` row plus re-click supersede is the recovery, not a reconciliation job.
- ~~Duplicate pairing has no guard.~~ Closed: `issueTx` revokes every prior unrevoked cert for the device inside the same persist tx (`certificate.go:59`), so re-running Issue supersedes instead of accumulating - one live (`revoked=false AND status='active'`) cert per device is now an invariant.
- **Abandoned pairing is only DB-visible.** Pair-page status derives purely from `GetActive` (`admin_pair.go:131`), which counts only `status='active'` rows; a `pending`/`failed` row shows "unpaired" there (surface it via `/admin/observability` cert tiles). Divergence from device NVS reality still has no reconciliation/health job.
- **Revocation is not broker-enforced (no CRL/OCSP).** Revoke flips the DB row + deletes the dynsec client; a still-valid cert is kept out only by the dynsec delete (`admin_pair.go:576`).

---

Related: [`../operator-role.md`](../operator-role.md), [`../security-review-checklist.md`](../security-review-checklist.md), [`alerts.md`](alerts.md).
