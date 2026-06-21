# Security scanning

Two scanners gate merges on `dev` + `main`:

- **govulncheck** - Go vulnerability database, reachable-symbol scoped.
- **gosec** - static analysis for hardcoded creds, weak crypto, SQLi-shaped string concat, etc.

Plus an image CVE scan (the app now ships in a container):

- **Trivy** - scans the built docker image for OS-package + dependency CVEs. Runs in the `deploy` workflow before push, **report-only** (never blocks a deploy yet).

## Run locally

```bash
make sec-tools     # one-time: install pinned scanner binaries to $GOBIN
make sec           # govulncheck + gosec at the gate severity
make sec-vuln      # govulncheck only
make sec-static    # gosec only (HIGH severity gate)
```

`make sec` exits non-zero on any HIGH-severity gosec finding or any reachable govulncheck CVE. CI runs the same targets via `.github/workflows/ci.yml`.

## CI

`.github/workflows/ci.yml` runs on every push to `main` and every PR (to `main` / `dev`). The `govulncheck` and `gosec` jobs are separate so a failure points at exactly one tool. The gosec SARIF report is uploaded to GitHub code scanning.

### Image scan

Container image vulnerability scanning (Trivy) runs in the deployment pipeline against the built image, so it scans exactly what ships. It is operated outside this repository. CI here gates on source-level scanning (govulncheck + gosec).

## Adding an exception

Two paths depending on what's being suppressed.

### Suppress one finding inline

Add a `// #nosec G123 -- <reason>` comment at the offending line. Reason must be specific (link to issue, explain why). Example:

```go
// #nosec G304 -- path is constructed from a typed enum, not user input.
data, err := os.ReadFile(certPathForEnv(env))
```

### Disable a rule globally

Edit `.gosec.json`:

```json
"rules": {
  "G404": {"enabled": false, "reason": "math/rand seeded for non-crypto telemetry sampling, not auth"}
}
```

Both forms require a second-human review nod and a comment that explains *why*. When the suppressed code changes, re-evaluate whether the suppression is still needed.

## Adding a CVE exception

govulncheck doesn't support inline silencing. If a reachable CVE has no upstream fix yet:

1. File an issue tracking the upstream fix.
2. Add a build-time guard or a runtime mitigation that breaks the reachability path.
3. Re-run `make sec-vuln`. If govulncheck no longer reports the CVE, you're done.
4. If it still reports, you need to either pin to a different version or accept the gate failure on the affected branch (and tag the relevant commits with the issue link).

Do NOT skip the security workflow with `[skip ci]` or branch protection bypass to push past a vuln. The gate is the point.

## Updating tool versions

Pinned versions live at the top of the Makefile:

```
GOVULNCHECK_VERSION ?= v1.1.4
GOSEC_VERSION       ?= v2.25.0
```

And in `.github/workflows/ci.yml`. Update both together. Re-run `make sec-tools && make sec` locally first; some new gosec releases ship new default rules that fire on existing code, requiring inline `#nosec` adjustments before a clean upgrade.

## Why these tools

- **govulncheck** is the official tool from the Go team. Its database is updated with every Go release plus continuously between releases. Reachable-symbol scoping means it only fails on CVEs whose vulnerable function the binary actually calls - not just on transitively-imported packages.
- **gosec** is the most active Go SAST. Rule coverage maps cleanly to OWASP Top 10 patterns. SARIF output integrates with GitHub-compatible code scanning UIs.
- Both are Go-native, single-binary, no daemon, run in CI in seconds.
- **Trivy** is the next addition (filesystem + container + Go binary scanning); complements rather than replaces these two.

## Files

- `Makefile` targets: `sec`, `sec-vuln`, `sec-static`, `sec-tools`.
- `.github/workflows/ci.yml` - CI gate (lint, tests, govulncheck, gosec).
- `.gosec.json` - rule overrides + allowlist + exclude paths.
- `docs/security.md` (this file).

## CA private-key protection

The internal CA in `pkg/pki/` signs every per-device mTLS client
certificate, so its private key is the load-bearing root of
multi-tenant device identity. Compromise = forge certs for any
device CN in any tenant, bypass dynsec ACL, impersonate devices.

### Current state (medium-term defence)

`THESADA_CA_KEY_PASSPHRASE` encrypts the on-disk `ca.key` with
AES-256-GCM under a scrypt-derived KEK (N=32768, r=8, p=1). When set:

- `pki.Bootstrap` writes new bootstraps as a `THESADA-CAKEY-V1`
  envelope.
- Existing plaintext installs migrate with one command:
  `THESADA_CA_KEY_PASSPHRASE=... thesada-app ca-encrypt` rewrites
  the key file as an envelope and preserves the plaintext form at
  `ca.key.plaintext.bak` for the operator to delete after
  verifying the next normal boot loads cleanly.
- Wrong passphrase against an encrypted file fails loud (AEAD
  authentication error), it never falls back to "try plaintext."

When empty: legacy plaintext PEM on disk. Boot logs a
`CA bootstrap warning` naming the exposed file path so the
operator sees the exposure on every restart, not just at install
time.

Threat model covered: backup-leak, sidecar volume mount,
cold-disk theft, ad-hoc operator `cat ca.key`. Not covered:
live-process memory compromise (the decrypted key sits in process
memory after boot). The passphrase itself must be sourced from
something *not* on the same disk: systemd `LoadCredential=`,
kubernetes `Secret`, vault agent, sealed-secrets-rendered env.

### Long-term plan (HSM / KMS)

The correct long-term posture is to move the
private key off the server entirely:

| Path | What changes | Trade-off |
|---|---|---|
| AWS KMS asymmetric key + sign API | `pki.CA.SignDeviceCert` calls `kms:Sign` for every cert issue. Private key never leaves KMS. | One AWS dependency, per-sign latency. |
| GCP KMS asymmetric / Cloud HSM | Equivalent to AWS; different cloud dependency. | Same. |
| Vault `transit` engine with `sign` operation | Self-hostable, single component to add. Private key lives in Vault's encrypted storage; signing happens server-side in Vault. | Operates Vault. |
| YubiHSM2 / softhsm + PKCS#11 | Hardware-bounded private key. | Hardware procurement + PKCS#11 plumbing. |

All four share the same interface change in this codebase:
replace `*ecdsa.PrivateKey` in `pki.CA` with a `crypto.Signer`
interface, swap the `ecdsa.Sign` call inside `SignDeviceCert` for
`signer.Sign(...)`. Backend selection lands behind a `CAKeyProvider`
config var (`local`, `kms`, `vault`, `pkcs11`). The encrypted
envelope path stays as the `local` provider.

This work becomes mandatory before any deployment where the operator
does not fully control the server's physical environment or backup access.
