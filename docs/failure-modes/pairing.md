# Failure modes: device pairing (app side)

`failure -> detection -> recovery` for the app side of the fw pairing flow (`pkg/web/admin_pair.go`). The firmware side lives in [`../../../thesada-fw/docs/failure-modes/mqtt.md`](../../../thesada-fw/docs/failure-modes/mqtt.md). A blank recovery cell is a gap.

There is **no app-side bearer pairing token**: pairing is gated by super-admin session auth (404 to hide the surface), and device identity is asserted by MQTT `device_id`. The anti-spoof control is the cross-tenant pairing guard `FindActivePairingTenant` (`pkg/service/certificate.go:116`), which logs + drops on tenant mismatch.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| mTLS provisioning fails mid-flow (cert/config/secret push) | Each step returns `(msg, ok)`; failure -> `slog.Error(...)` + `?error=` FlashErr on the pair page (`admin_pair.go:202`) | Manual re-click; push-first/persist-last + idempotent (secret.set overwrites, dynsec "already exists" tolerated) |
| Cert minting fails (`SignDeviceCert`) | `slog.Error("sign device cert failed")` -> `error=sign+failed`; CA not initialized -> `error=CA+not+initialized` (`admin_pair.go:176`) | Fix CA / passphrase, retry |
| DB persist fails after MQTT pushes succeed | `slog.Error("persist device cert failed")` -> `error=persist+failed` (`admin_pair.go:278`); `Issue` itself atomic | Re-click Issue |
| dynsec role/client create fails | `slog.Error("dynsec create... failed")` (`admin_pair.go:265`) | Retry ("already exists" tolerated) |
| Post-pair `cli/restart` publish lost | `slog.Warn("pair issue: cli/restart publish failed")` (`admin_pair.go:293`) - but pairing already marked done | Best-effort; device keeps old port until manual restart / watchdog |

## Gaps

- **Pair flow is not transactional (#68-class).** An MQTT-push + DB-persist sequence not wrapped in a transaction: a partial NVS write persists on the device while `paired_at` is never flipped -> **DB shows unpaired while the device is half-provisioned.** No reconciliation. Mitigated (not guaranteed) by idempotent re-click (`admin_pair.go:154`).
- **Duplicate pairing has no guard.** `Issue` does not revoke the prior active cert; each Issue click INSERTs another non-revoked `device_certificates` row (`certificate.go:39`). `GetActive` just picks newest -> multiple active certs accumulate silently. `Revoke` clears all at once, papering over it.
- **Abandoned pairing is invisible.** Pair-page status derives purely from `GetActive` (`admin_pair.go:130`); a device with partial NVS but no cert row shows "unpaired" - divergence from device reality has no reconciliation/health job.
- **Revocation is not broker-enforced (no CRL/OCSP).** Revoke flips the DB row + deletes the dynsec client; a still-valid cert is kept out only by the dynsec delete (`admin_pair.go:437`).

---

Related: [`../operator-role.md`](../operator-role.md), [`../security-review-checklist.md`](../security-review-checklist.md), [`alerts.md`](alerts.md).
