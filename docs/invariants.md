# thesada-app invariants

The load-bearing rules this application relies on. Every PR that
touches a listed area must keep these true. Violations require this
file to be updated with a justification, not silent landing.

Dated 2026-11-19 (the `config.json` write guard passes an empty scalar secret the device holds in NVS and names each field it refuses, open WiFi networks pass with the KEK unset, an `ota.*` command other than `ota.status` counts as a config change, the secret key pattern also covers `pass`, `pwd`, `psk`, `pin` and `seed` and counts `null` as empty, and a bare legacy WiFi password is dropped, not re-keyed, when the stored `config.json` names another primary SSID. Same day, earlier: a verified WiFi clear tells the legacy re-key from a save by the row's `rekeyed` flag, which only the re-key sets and every other write clears, so a save of the same password during the clear is kept, and the clear's mark reads both rows under the device row lock). Previously 2026-11-18 (a verified WiFi clear drops a legacy password re-keyed while the device cleared, and a re-keyed legacy password stays a device override beside a tenant default. Same day, earlier: a verified WiFi clear keeps a password saved while the device cleared, and each tenant default fan-out target has its own budget for the row lock wait and the push. Same day, earlier: firmware 1.4.5 is the supported floor: a staged write and a tenant rule push to older or unknown firmware are refused before anything is sent, and a drift pull skips the device with one log line. A verified WiFi clear drops the bare legacy row too unless a stored config names another primary SSID, a tenant default fan-out skips a device that gained an override under the device row lock, a dropped stale read logs no save, and a not-done chunk without a length fails the read. Same day, earlier: one state model for device WiFi credentials: an open marker is a fact about `config.json`, the write guard also asks a correlated `secret.info` that NVS holds nothing for the SSID, every device reply that feeds a stored fact needs the echoed `req_id`, a bare legacy `wifi.password` row is re-keyed once to the primary SSID and inert afterwards, and Clear on device refuses a tenant default and reports a failed row drop). Previously 2026-11-17 (a chunked `fs.cat` read fails on a reply without the offset it asked for or for another one. Same day, earlier: the mark before a config write or command stamps the end of its claim, so a read during it stays stale when the closing mark fails, a CLI `fs.*` with a glob counts as a config change, `SetSecret` locks the device row before its insert, and a `secret.info` key two fields share is not verified. Same day, earlier: a reassign to the device's own tenant writes nothing, a channel edit locks the row before it reads the old address, and the config write worker renews its claim after the guard). Previously 2026-11-16 (a device read of config.json only fills gaps in the secret store and never overwrites a stored secret, an open WiFi network is a marker in `device_open_networks`, staleness is `devices.config_changed_at` in the database, a stale read writes nothing, provisioning never sends an empty value, and Clear on device sends `secret.clear`). Previously 2026-11-11 (pairing a device into a tenant with no alert subscription subscribes the claiming user, else the oldest tenant admin, else the oldest user, to all devices at warn on their account email, once per tenant. The devices and alerts pages say so while a tenant with a paired device has no subscriber on an enabled channel. `cert.set` and `secret.set` travel in the req_id envelope and correlate on it, only `fs.write` and `fs.append` chunks stay raw. A dynsec reply is matched on its correlationData before it takes the waiter's slot. The retained-topics manifest is cached from a live delivery too. Every drift-pull CLI round trip runs under `THESADA_CLI_REQUEST_TIMEOUT`. A page renders into a buffer and is sent only when the whole template ran, so a template error answers a clean 500, and an error status page keeps its HTML Content-Type. Every admin redirect carries a registered flash code, the user edit page renders them, and the settings page names every `err` code it is sent. A write to the snapshot key `config.json` goes to the device as `/config.json`. `secret.info` fields keep SSIDs with spaces). Previously 2026-11-10 (templates carry no inline event handlers, the nonce CSP blocks them: forms confirm through `data-confirm` and a toggle submits through `data-autosubmit`, both handled by the nonced layout script). Previously 2026-11-10 (an operator handover in the tenant rules editor needs at least one rule: a save that parses to zero rules over a non-empty operator script answers 409 and the operator's script stays, and the editor seeds the rules block for an operator on a managed slot). Previously 2026-11-10 (a trend rule accepts a slash-separated metric such as `current/house_pump`, the name MQTT ingest stores for a sensor sub-path). Previously 2026-11-09 (a tenant rules editor at `/devices/{id}/rules` takes Blockly JSON only: the server parses it against a closed block set (`pkg/rulesgen`), generates the Lua, quotes every user string as a Lua literal, and pushes only Lua it generated again from the saved workspace. A tenant admin or the device owner may save and push, other tenant users only view. A slot an operator saved from the admin editor is neither shown nor overwritten by a tenant, and an operator saving in the tenant editor hands it over). Previously 2026-11-09 (a numeric reading checks the tenant's trend rules in one statement on ingest, a rule raises one `trend.<metric>` alert per episode, raises again after its window and clears when the move ends). Previously 2026-11-08 (the account's own email channel follows `users.email`: its target is read at send time, so an email change moves alerts with it, and only label and enabled are editable on it. User-added email channels stay plain targets). Previously 2026-11-08 (an alert goes to the user's enabled notification channel rows, once per channel. 0043 turned the account email, `users.telegram_chat_id` and each webhook destination into channel rows and linked every subscription. A telegram rule without a chat id stays unlinked, as it never sent. The old columns stay one release, read-only apart from the webhook mirror kept for a rollback). Previously 2026-11-08 (a password or magic-link login whose account holds a passkey challenges before any session, the web page offers the key, the code or both, and the JSON logins answer `passkey_required` for a passkey-only account instead of skipping the factor. A passkey assertion whose sign count did not grow is refused, and the guarded counter `UPDATE` is the single winner of two parallel assertions. Each ceremony is server side with a 5-minute TTL and is used once. Adding or removing a key re-checks the password). Previously 2026-11-08 (tenant delete reads the tenant uuid again after listing its devices and refuses a tenant created again under the slug, so a replacement's devices never enter the cascade. A link mail's account lookup and token insert share a 10 s deadline, so a stalled database frees its slot. The per-device delete lock lives only while held or awaited, and a job canceled while waiting for it starts nothing. A rename readback chunk must answer the offset asked for. 0041 fills only certs issued at or after the claim it takes the key from. A bulk OTA publish that timed out is reported unknown, not failed). Previously 2026-11-08 (a device delete holds a per-device lock from its fresh ownership read through the DB delete, and a reassign of that device is refused meanwhile. A broker identity lookup from a stale snapshot of an unpinned device is `ErrBrokerSnapshotStale`, so teardown deletes neither tenant's client and alerts. A timed-out `fs.mv` counts as landed only when the destination's bytes equal the content, and a write worker renews its claim before its first step or aborts. The boot orphan sweep has one 30 s budget across its retries. Link mails run at most 16 at once and drain on shutdown. Form bodies are capped by the same media type parser `ParseForm` uses. 0041 takes a key only from an enrollment claimed into the device's own tenant). Previously 2026-11-05 (a device's broker identity is recorded under the tenant it was issued in, every teardown uses that tenant, and a second device row can hold neither that identity nor its live CN). Previously 2026-11-05 (admin enrollment reset keeps a claim another tenant backs and clears orphan claims, boot sweeps those orphans under timeouts, and shutdown lets the device in progress finish before MQTT and the pools close). Previously 2026-11-05 (a device file write runs one per device, stages in `<path>.new`, and renames into place only after every chunk ack and the committed size check pass, so a failed or overlapping save never truncates `/config.json`). Previously 2026-11-05 (a retained sensor delivery is dropped before it can bump last_seen_at, clear absence or store telemetry, and every goroutine that device or request input reaches runs under `pkg/safego`, which logs a panic as `goroutine.panic` with its stack, and an alert dispatch that panics counts as one delivery attempt). Previously 2026-11-03 (bulk delete and tenant delete run their device cascade as a job on `/admin/jobs/{id}` that the page polls, so a long fleet cannot hit the edge proxy timeout). Previously 2026-11-03 (a broker teardown that fails on single, bulk or tenant delete is flagged on that device's `device.delete` audit row and on the page, because the device alert cascades away with the row, and the tenant delete form carries the serial recovery override). Previously 2026-11-03 (tenant delete walks every device through the device delete cascade first and the service refuses a tenant that still has devices, so a deleted tenant's serials answer revoked and its broker clients are torn down or named in the audit row). Previously 2026-10-06 (a tenant at its abuse cap cannot add a user, a new device, or another alert that day; updating a device that already exists still lands, and zero turns that one cap off). Previously 2026-09-29 (admin list, pair, and secret pages render flash from a registered code, so a crafted query cannot put words on the page). Previously 2026-09-29 (a device asks POST /devices/enroll/status with a signed serial and is told active, revoked, or unknown; only revoked for that serial wipes the cert, and a deleted device's serial is kept so the answer survives the row). Previously 2026-09-28 (the owner of a claimed device can revoke it; that path clears enrollment under a row lock that refuses another tenant's claim, before the cert revoke and cert.clear, and never hands the device to the fallback credential). Previously 2026-09-26 (ten wrong claim-form codes lock that device id until the earliest verified row announces the token already stored for it; an unverified or later key does not clear the lock). Previously 2026-09-25 (a device is told THESADA_MQTT_DEVICE_HOST, never the app's broker URL; a new claim token is stored as an HMAC when THESADA_CLAIM_HASH_KEY is set and a legacy SHA-256 still matches). Previously 2026-09-23 (magic-link limiter checks the client IP before the address cap, that cap sits above one client's budget, an address rejection does not spend the client's cap, and the two caps are reserved together). Previously 2026-09-05 (retained MQTT deliveries never act as live; legacy cli/response tap removed; revoke and delete gate on the recovery path. Prior: device CLI pulls gated on pairing state; hands-off
recovery refuses to run when the shared fallback credential is not
connectable; unauthenticated device enrollment surface; device-facing
enrollment endpoints address the row by its primary key and the claim
form refuses an ambiguous token). Previously 2026-07-11 (X-Forwarded-Proto gated on trusted proxies; CSRF
cookie HttpOnly; WS hub binds the effective tenant; alert email channel
fails loudly when SMTP is unconfigured). Previously 2026-07-10 (alert
delivery lifecycle: retry with backoff,
dead-letter budget, startup + periodic redispatch sweep, bounded
insert retry. Same day, earlier: alert Dispatch tenant-scoped through
`db.WithTenant` so RLS returns rows; pools-app guard limitation
noted).
Previously 2026-07-01 (device-config secrets complete: provision-at-pair via
`secret.set`, write-only UI, root-KEK rotation, existing-device backfill,
field keys aligned to the firmware keymap - phases 5-7). Previously
2026-06-30 (device-config secrets phases 2-4: per-tenant DEK envelope
encryption, write-only contract, crypto-shred on tenant delete, RLS on
the two new stores, malformed-KEK boot failure, config-field blanking).
Previously 2026-06-22 (auth-layer hardening: password-login rate limiting,
constant-time login, super-admin guard on impersonation, service-layer
password floor, signed-double-submit CSRF, cookie-secret length hard-fail).
Previously 2026-06-16 (CI lint guard for the pools.App tenancy contract,
session token rotation, CA key encryption at rest, MQTT topic / cert
pairing tenant gate, RLS ungated as the steady-state default). Bump the
date on every edit.

Entries marked **WIP** describe target state that is not yet enforced
end-to-end. They live here so the audit surface is visible.

---


## Device CLI and recovery

### Config pulls over the device CLI require a paired device

Snapshotting talks to a device over the MQTT CLI. An unpaired device is
connected on the shared onboarding credential, and firmware refuses
`fs.ls` and `config.dump` on that connection, so a pull yields one
timeout per file and no data. A device with no `paired_at` also has no
operator-approved config worth storing.

How enforced: `handleInfo` calls `devicePaired` before any drift work.
The rule itself is the pure `snapshotAllowed(pairedAt)` in
`pkg/mqtt/mqtt_snapshot.go`, tested in `snapshot_gate_test.go`. A
lookup failure resolves to unpaired and logs the skip - not a silent
fallback: guessing "paired" costs a burst of refused CLI requests.

### A device file write never leaves the live file half written

This holds for every device file write: the config editor and snapshot
restore through `/admin/devices/{id}/config/write`, and the tenant rules
push (`POST /devices/{id}/rules/push`), which runs the same `runCLIWrite`. One runs per device
at a time. A second write to a device while one runs gets 409 before
anything is sent. The chunks go to `<path>.new`, never to `<path>`. The
app sends `fs.mv <path>.new <path>` only after every chunk ack named the
staged path with its full byte count and a correlated `fs.cat` reports a committed
size equal to the content, and LittleFS applies that rename as one
metadata commit. A failed, short or unanswered step removes
`<path>.new` with `fs.rm` and marks the request failed, so
`/config.json` stays the last good file and the next boot does not fall
back to defaults. `fs.mv` prints its failure with `ok:true`, so only a
`Renamed` line counts. An `fs.mv` whose reply timed out is settled by
reading back: the staging copy still there means no rename, and the
rename counts only when `<path>` reads back byte for byte as the content,
otherwise the outcome is reported unknown. The worker renews its claim
before its first step, and aborts if another write took over meanwhile.
Config snapshots are keyed `config.json` without a slash, and firmware
refuses a path without one, so `stagedWrite` sends that key to the device
as `/config.json` while the snapshot row keeps its key. Paths with whitespace, `*` or `?` are refused
before anything is sent, since the device shell splits and globs them.
Paths on `/sd` are refused too, because FAT rename does not replace an
existing file. A command from the config page CLI box that can change
`config.json` takes the same claim. Not covered: a second app instance
(the claim is in memory), a hand-typed `fs.*` command on another file from
the CLI box, and anything sent from the MQTT shell page.

How enforced: `claimDeviceWrite` and `stagedWrite` in
`pkg/web/admin_config.go`, tested in `admin_config_write_test.go`
(command sequence, every failure step, ack path, size check, `/sd`) and
`admin_config_integration_test.go` (the same over a real broker, plus
the 409 for an overlapping write).

### A stored device reply echoes its request id

A device reply that feeds a stored fact (a snapshot, a store row, a marker,
a row delete, a write-landed decision) counts only when it echoes the
request's `req_id`. The rule lives in one place: `CLIRequest` sets
`CLIResponse.Correlated` when every page of the reply carried this
request's id, and `CLIRequestStateful` / `CLIRequestFieldsStateful` return
`ErrUncorrelated` otherwise. A payload that cannot travel in the envelope
is never sent on the stateful path.

| Caller | On an uncorrelated reply |
|---|---|
| every `ReadFileChunked` chunk (drift script pull, Load from device) | the read fails, nothing stored |
| drift `config.dump` | nothing stored |
| CLI box `config.dump` | the box shows the reply, no snapshot |
| `secret.info` after Provision to device or a blank-SSID clear, and in the write guard | not verified, the guard refuses |
| `secret.clear` and the empty `secret.set` of Clear on device | not confirmed, the store row stays (`nvs_clear_uncorrelated`) |
| the write's size check of `<path>.new` | the write fails, no rename |
| the readback after a timed-out `fs.mv` | the outcome is unknown |

Raw `fs.write` and `fs.append` chunks stay matched on the command name:
JSON escaping would grow a chunk past the device input buffer. The secrets
page's own `secret.info` display read accepts any reply.

Firmware 1.4.5 (`service.MinFirmwareVersion`) is the supported floor, the
first build that echoes `req_id`. The version is the device's reported
`firmware_version`, an unknown or unparsable one counts as below.

| Path | Below the floor |
|---|---|
| staged write (`config/write`: Save, Restore, script saves) | 409 naming 1.4.5 before the claim, nothing sent |
| tenant rule push (`/devices/{id}/rules/push`) | 409 naming 1.4.5 before the claim, nothing sent |
| drift pull on an info publish | skipped, one `drift pull skipped, firmware below the supported floor` line per publish |
| CLI box, Load from device, secrets page | sent as before, a stored fact still needs the `req_id` |

How verified: `pkg/service/firmware_floor_test.go`
(`TestFirmwareMeetsFloor`), `pkg/web/firmware_floor_integration_test.go`
(`TestFirmwareFloor`: 1.4.4 and unknown refused with no command sent, 1.4.5
writes and pushes), `pkg/mqtt/firmware_floor_integration_test.go`
(`TestBrokerDriftFirmwareFloor`), `pkg/mqtt/correlation_integration_test.go`
(`an_uncorrelated_config_dump_is_not_stored`,
`an_uncorrelated_fs_cat_chunk_fails_the_read`,
`a_correlated_read_still_stores`,
`cli_request_stateful_refuses_an_uncorrelated_reply`),
`pkg/web/correlation_integration_test.go`
(`cli_box_config_dump_shows_output_but_stores_no_snapshot`,
`uncorrelated_secret_info_verifies_nothing`,
`uncorrelated_secret_clear_keeps_the_store_row`,
`uncorrelated_secret_info_after_a_blank_ssid_clear_keeps_the_row`,
`uncorrelated_size_check_fails_the_write`),
`pkg/web/admin_config_write_test.go`
(`TestStagedWrite_UncorrelatedSizeCheckDoesNotRename`, the readback case
`destination chunk without req_id`), `pkg/mqtt/paged_response_test.go`
(`TestAwaitPagedCLIResponse_MixedReqIDsClearTheID`).

Source: `pkg/mqtt/mqtt_cli.go`, `pkg/mqtt/mqtt_snapshot.go`,
`pkg/web/admin_config.go`, `pkg/web/admin_secrets.go`.

### The device enrollment surface is an oracle for nothing

`POST /devices/enroll`, `/enroll/verify`, `/enroll/cert`, `/enroll/ack` and
`/enroll/status` are the unauthenticated device-facing endpoints, and they
answer from the public internet. A factory-fresh device has no credential to
authenticate with, so the guards are rate limits, a claim token and an Ed25519
proof instead. The status check is the one call a device makes after it
holds a cert: see "A stored cert is wiped only on an explicit revoked" below.

| Rule | Why |
|---|---|
| every state-dependent refusal returns the same 403 body, rate limits and a missing CA included | otherwise a caller distinguishes a real device_id from a fabricated one. A 429 is device-id-keyed, so it reports that somebody else is enrolling that id; a 503 for a nil CA was the one answer available without spending a rate-limit token. Server-side failures are the exception and stay 500 with their own bodies (`sign failed`, `persist failed`, `seal failed`): none of them depends on which device_id was asked for, so a caller cannot pick which one it gets |
| announce never refuses on enrollment state - any well-formed id gets 200 and a challenge | sealed, frozen and already-claimed are answers to "is this id real", and the ids are guessable. The refusal moves to `/enroll/verify`, behind the claim token and the signature; on the wire it is still the uniform body, so the state never leaves the process |
| 204 "keep polling" is issued only after the claim token verifies | polling must reveal nothing the caller has not already proved it knows |
| rate limited per source IP **and** per enrollment, where an enrollment is `(device_id, pubkey_hex)` | per-IP alone lets one host walk many ids; per-enrollment alone lets many hosts hammer one. Keyed on the id alone the bucket was shared between a real device and anyone who guessed its id, and every certificate poll spent from it, so one guess starved the hardware for the rest of the hour |
| the per-device_id bucket survives but only announce spends it | announce is the only endpoint that creates rows, so that bucket bounds how much of the table one guessable id can occupy. Verify, cert and ack never touch it, so a flood cannot gate a device that has already announced. Residual, accepted: a sustained flood can still delay a first announce on that id by up to the window |
| the per-IP token is spent before device_id and pubkey are validated, and both are validated before they are used as a map key | the `byPair` limiter keys a map on two body fields from an unauthenticated caller, so without a shape check the caller chooses how much memory the process uses. All three limiters run `StartSweeper` |
| rate-limit key is `httpsec.ClientIP` with trusted proxies | `RemoteAddr` alone looks safer and is not: behind a reverse proxy every device shares one address, collapsing the per-IP limit into a single global bucket for the fleet |
| request bodies capped via `MaxBytesReader` | an unauthenticated caller must not set the memory budget |
| an enrollment is identified by `(device_id, pubkey_hex)`, never by `device_id` alone | MACs are sequential, so one unit reveals its neighbours' ids. Pinning a key on either arrival OR proof lets a squatter own the id: a signature proves possession of *a* private key, not of *the* device's, so the squatter can complete the proof with its own keypair and lock the real hardware out forever. Keyed on the pair, the squatter lands on its own row and the real device keeps its own |
| every device-facing request names both halves of that identity, and the row is addressed by the primary key | the device always knows its own public key. `claim_token_hash` has no unique constraint, so a lookup by token alone returns whichever row sorts first: a squatter who photographed the QR could announce the SAME token under a keypair ground to sort ahead, and the real device's certificate poll would resolve to the squatter's claimed row and hand the hardware a certificate and private key for somebody else's tenant |
| the signature at `/enroll/verify` is checked against the pubkey the caller named | selecting the row any other way lets a caller advance a row it cannot sign for. The claim token plays no part in verify: it does not identify a row and the signature already proves the key |
| the claim token still has to match the row the caller named, at `/enroll/cert` and `/enroll/ack` | the pubkey is public - it is in the QR and on `chip.info` - so the primary key alone is not a credential. Without the token check anyone who read a key could collect a certificate or seal a row before the device does |
| the human claim form is the one token-only lookup, and it refuses an ambiguous match | a person cannot supply a pubkey, so the token has to resolve alone. When several rows carry it, only a verified-and-unclaimed row can be claimed at all; if that leaves exactly one the user still gets their device, otherwise the claim is refused. Picking one by ordering shows a success page for a row the user did not mean |
| a claim already held by the caller's tenant and user replays instead of refusing | the handler provisions the broker after the claim commits and tells the user to retry on failure. `ClaimAllowed` refused that retry, so the answer was "already claimed" for a device that held a certificate and had no broker client. The replay returns the same `devices` row and does not move `claimed_at`; another tenant or another user still loses to the first claim |
| claim token is frozen once `verified_at` is set, silently | announce is unauthenticated and `device_id` is readable from the soft-AP BSSID, so a rotatable token on a verified row hands an attacker the certificate AND private key. Silently, because a distinguishable refusal is the oracle above |
| challenge is burned before the signature is judged | a failed attempt must not leave a nonce to grind against |
| stale unclaimed rows are pruned on a schedule (`EnrollmentService.StartPruner`, `THESADA_ENROLLMENT_PRUNE_INTERVAL`) | these rows are the only thing in the schema an unauthenticated caller can create, and nothing else removes them |
| every revoke path calls `EnrollmentService.Reset` | `device_enrollments` has no FK to `devices`, so the delete cascade misses it. A sealed row refuses announce forever, which is a revoked device bricked short of manual SQL. The spec: "next POST starts a fresh cycle" |
| admin `Reset` takes the device's tenant: it deletes unclaimed rows, that tenant's claims, and orphan claims. A claim another tenant backs stays | `device_id` is unique per tenant only, so another tenant can hold a live claim on the same id. A pending claim is an orphan when its tenant has no device row for the id. A sealed one is an orphan unless its tenant has a device row holding a cert for the claim's key, or a live cert with no stored key (issued before 0031 or by admin pairing), because a reassign moves the row and its certs but not the claim, and a later phantom row in the old tenant does not make that claim live. It locks the id's rows first and deletes orphans in a statement of their own, so a claim that commits meanwhile is seen with its device row. When the admin pool does not bypass RLS the orphan arm is skipped, since every claim would read as an orphan |
| boot runs `EnrollmentService.SweepOrphanClaims` before MQTT and HTTP start, with a 5 s lock timeout, a 20 s statement timeout and a 30 s overall bound, logging each row it clears | a delete cut off between `DeleteByID` and the reset, or a reassign, leaves a claim no admin path can reach. A held lock or a slow database must not stall boot, and a pool without BYPASSRLS refuses the sweep instead of deleting every claim |
| the enrollment is sealed by the device's ack, never by the handler that returns the cert | sealing before the body is flushed bricks the device on any mid-flight failure; letting the device close the loop makes the failure mode a retry, and `Issue` revokes the superseded cert |
| the cert response carries tenant, topic prefix, broker host and port | the CN, the broker ACL and ingest are all keyed on tenant, and the firmware default prefix belongs to no tenant - without these the device holds a valid cert it cannot use |
| the broker host in that response is `THESADA_MQTT_DEVICE_HOST`, and an unset or unusable value refuses the cert | the app's own broker URL is how this process reaches the broker. On a compose network that name does not resolve for a device, so deriving the host from it strands a unit that just stored a good certificate |
| a new claim token is stored as HMAC-SHA256 under `THESADA_CLAIM_HASH_KEY` when that key is set; verification accepts that digest or the legacy unsalted SHA-256 | the token is the bearer credential for the certificate. A database read of an unsalted hash of an 8-digit code is a lookup table. Rows written before the key existed must keep matching |
| ten wrong codes on the claim form lock that device id until the earliest verified row announces the token already stored for it | the code is short on purpose. The counter is the worst `claim_failures` across the id's rows, so a squatter row cannot hide a locked real one, and the lookup locks those rows. A tie on `verified_at` yields to the smaller pubkey. An unverified announce, or a later key, does not clear the others. A logged-in caller is told the form is locked; an unknown id stays not-found |
| the response never carries the device CA | it is the broker's client-verification CA; a device that installed it over its own trust anchor loses MQTT and OTA |

`device_enrollments` carries no tenant and no RLS, which is deliberate and
justified in migration 0028: an unclaimed device belongs to nobody, and a
nullable `tenant_id` with an `IS NULL OR` carve-out is the anti-pattern
CODE-GUIDELINES names. Access is confined to `EnrollmentService`, which runs
every statement through `db.WithAdminAudit` so each touch leaves an audit line.
The table is granted to `thesada_app_admin` only, so on a two-role deployment
the tenant-scoped role cannot reach an unscoped table. That separation is a
deployment property, not a code one: `THESADA_DATABASE_URL_ADMIN` defaults to
`THESADA_DATABASE_URL` (`pkg/config/config.go`), and `main.go` opens a second
pool only when the two differ, so a single-role deployment runs both pools as
the same role and the grant stops distinguishing them. The `WithAdminAudit`
line is logged either way.

Several rows per `device_id` are expected, not a fault - one per keypair that
announced under it. They are bounded by the per-device_id rate limit and
removed by the pruning sweep. There is deliberately no unique index over
claimed rows per `device_id`: it would re-introduce the lockout above, with an
authenticated squatter permanently blocking the real owner's claim. What is
NOT closed by any of this: a caller with an account can claim a row it squatted
into its own tenant. It gets a certificate for a phantom device in its own
tenant, scoped to its own topic prefix, and the real hardware is unaffected -
an operator clears the litter with a revoke, which calls `Reset`.

A squatter who photographed the QR can go further and announce the SAME claim
token under its own keypair. That is the accepted model - possession of the
label is authority - and the device-facing endpoints are unaffected, because
they address the row by its primary key. The visible cost is on the claim form:
while both rows are claimable the owner's claim is refused as ambiguous. It
resolves as soon as only one row can still be claimed, and the operator remedy
is the same revoke, after which the device mints a fresh token on its next
portal session and the photographed one is worthless.

Claiming is a web form (`authmw.RequireAuth` + `csrf.Middleware`) and
`POST /api/v1/devices/claim` (`RequireAuthJSON`; a cookie caller still passes
`APICSRFGuard`). Both share `THESADA_DEVICE_CLAIM_MAX_PER_HOUR` (default 5)
and write `owner_user_id` and `mqtt_topic_prefix` in the same transaction as
the enrollment flip.

Source: `pkg/api/v1/enroll.go`, `pkg/api/v1/claim.go`, `pkg/service/enrollment.go`,
`pkg/service/enrollment_policy.go`, `pkg/web/device_claim.go`,
`migrations/0028_device_enrollments.sql`.

### A stored cert is wiped only on an explicit revoked

A unit that missed `cert.clear` cannot see the broker refuse it, so it asks
`POST /devices/enroll/status`. The body is device id, pubkey, cert serial,
unix seconds, and an Ed25519 signature over
`thesada-enroll-status\n<device_id>\n<serial>\n<ts>`. The serial in that
statement is canonical: lowercase hex, no leading zeros. The reply's `serial`
is that same form.

| Answer | What the device does |
|---|---|
| 200, `status` `revoked`, `serial` equal to the one it signed | wipe the cert and reboot into enrollment |
| 200, anything else (`active`, `unknown`) | keep the cert |
| non-200, including a database error | keep the cert |

| Rule | Why |
|---|---|
| the signature is checked against the pubkey in the body, and that pubkey must be the one stored with the serial | a signature only proves possession of some key. Accepting a caller-chosen key would make the endpoint a serial oracle, and would let a stranger answer revoked for a serial they do not hold |
| the timestamp must fall within 5 minutes of now | the firmware will not ask until NTP has synced, and a captured request must not stay reusable. The bound is the claim-challenge TTL |
| unknown covers a missing serial, a pubkey or device id that does not match, a pending or failed cert, and a cert issued with no identity key | the firmware wipes only on revoked. A null pubkey never matches, so admin pairing (no identity key) cannot be wiped by this path |
| a database error is 500, not 200 unknown | both keep the cert, and 500 is the firmware's backoff rather than a six-hour wait |
| status has its own limits: 600 requests per source IP per hour, 30 per `(device_id, pubkey)` per hour, and it does not spend the enrollment buckets | the firmware backs off at 150 seconds, which is 24 asks an hour. Sharing the enrollment budget would let a fleet's checks starve a first boot |
| enrollment stores the identity pubkey on the certificate | owner revoke deletes the enrollment rows, and the status check still has to know which key may speak for that serial |
| device delete copies those serials into `device_cert_serial_tombstones` in the same transaction, before the certificate rows cascade away | a deleted device must answer revoked. A serial with no pubkey is not copied, because nothing could prove the request |
| tenant delete runs every device through that same cascade first, and `TenantService.Delete` refuses while any device row remains, under a lock on the tenant row | a tenant cascade would drop the certificates with no tombstone, leave unclaimed enrollment rows and keep the broker clients. The lock makes a racing device insert wait and fail its FK instead |

Source: `pkg/api/v1/enroll.go` (`handleEnrollStatus`),
`pkg/service/cert_status.go`, `pkg/service/cert_status_policy.go`,
`pkg/service/device_delete.go`, `pkg/service/tenant.go` (`Delete`),
`pkg/web/admin.go` (`handleAdminTenantDelete`),
`migrations/0031_cert_serial_tombstones.sql`.

### Admin flash is a registered code

The device list, the tenant list, the tenant users and user edit pages, the
waitlist, the pair page, and the device and tenant secret pages render `ok`
and `error` only when the code was registered in `pkg/web/admin_flash.go`.
Anything else is blank, so no admin redirect writes flash text by hand
(`TestAdminRedirectsUseRegisteredFlashCodes`). Every registered
`error` code on the URL renders, so one redirect can name two failures. Counts, device ids,
field names, and broker errors stay in the log. They are not part of the
URL, because the URL is the one string a visitor can choose.

Source: `pkg/web/admin_flash.go`, `pkg/web/admin.go`, `pkg/web/admin_job.go`, `pkg/web/admin_pair.go`,
`pkg/web/admin_secrets.go`, `pkg/web/admin_tenant_secrets.go`,
`pkg/web/admin_devices_bulk.go`, `pkg/web/admin_device_delete.go`.

### Claiming a device requires proof of key possession, not the QR alone

A claim QR is a photograph. It survives on a shelf, a shipping box and a
support-ticket screenshot, so possessing the code is not possessing the
device. A device proves itself by signing a claim challenge with the
Ed25519 key it minted on first boot; the public half travels in the QR.

| Rule | Why |
|---|---|
| device id must match `thesada-` + 12 lowercase hex | operator labels from a hand-edited config are not unique across units |
| public key hex must be lowercase, 32 bytes | the key is an identity, so it gets one spelling |
| challenge must be non-empty | a signature over nothing proves possession but not participation in this claim |
| signature must be 64 bytes and verify | fail closed |

`VerifyDeviceProof` is deliberately stateless. Challenge freshness and
single-use belong to the caller, which owns the storage that makes a
challenge one-shot - without that, a captured signature replays forever.

Interop with the firmware signer is pinned by an RFC 8032 known-answer
vector rather than a live signing oracle. A command that signs
attacker-chosen bytes with the device key would be the claim attack.

Source: `pkg/pki/deviceproof.go`, `deviceproof_test.go`.

### Hands-off recovery never runs on an unusable fallback credential

`preemptiveCertClear` flips a device to the password listener, wipes its
client cert and reboots it. That leaves the device dependent on the
shared fallback credential. If that credential is disabled at the
broker, the device reboots into a broker that refuses it and needs
physical serial recovery.

How enforced: the handler probes `getClient` for the configured
fallback user once per request (`recoveryPath`) and hands the verdict to
`preemptiveCertClear`, which skips the sequence when it is not usable. A
probe error counts as unusable - an unreachable broker is not evidence the
credential works. Decision is `mqtt.RecoveryPathUsable(enabled, err)`,
tested in `recovery_guard_test.go`. The same verdict feeds the refusal
gate in the next section. A disabled client stays listed by
`listClients` and keeps its password, so presence is not evidence it
can connect; only the `disabled` flag is.

Fallback username is `THESADA_MQTT_DEVICE_FALLBACK_USER` (default
`mqtt`), not the application's own broker user.

Source: `pkg/mqtt/dynsec.go`, `pkg/web/admin_devices_bulk.go`.

## Tenant rules editor

### A tenant pushes only Lua the server generated from a closed block set

`/devices/{id}/rules` never accepts Lua from the browser. `rulesgen.Parse`
refuses any block outside `thesada_tenant_rules` and `thesada_tenant_rule`,
bounds every field (32 rules, 40-byte names, 120-byte messages, lowercase
codes), and `rulesgen.LuaString` writes each user string as a quoted literal
with quote, backslash and every control byte escaped. Push loads the saved
workspace and generates the Lua again, so a stored `lua_content` is never
trusted. The output keeps the firmware conventions: one alert per firing
through `Telegram.broadcast(msg, code)` with the MQTT fallback, string
methods only.

Who: an operator, a tenant admin (`users.is_admin`) of the device's tenant,
or the device owner may save and push. Any other tenant user sees the editor
read-only and gets 403 on save and push. A slot whose latest save came from
the admin editor (`source` not `tenant`) answers `managed` without its
workspace, and tenant save and push answer 409. The admin editor in turn
refuses to load a tenant workspace and locks its writes until the operator
takes the slot back.

An operator saving over a managed slot hands it to the tenant editor, but
only with at least one rule: a workspace that parses to zero rules over a
non-empty operator script answers 409 and the operator's script stays, so a
later push cannot replace it with an empty `rules.lua`. The editor seeds the
rules block for an operator on a managed slot, since the toolbox offers only
rule blocks.

How enforced: `pkg/rulesgen` goldens, a hostile-string golden and a Lua run
of the generated script against firmware mocks (skipped without `lua`),
`TestDeviceRules_RolesSaveAndRefusals`, `TestDeviceRules_PushWritesServerLuaAndReloads`,
`TestDeviceRules_OperatorHandoverNeedsRules`, `TestTenantRulesScriptSeedsRootForHandover`
(node harness), and the cross-tenant cases for every `/devices/{id}/rules` route.

Source: `pkg/rulesgen/`, `pkg/web/device_rules.go`,
`pkg/web/static/js/blockly-tenant-rules.js`.

## Tenant isolation

### A tenant cannot grow past its abuse cap

Defaults are 25 users, 50 devices, and 10000 alerts per day
(`THESADA_QUOTA_USERS`, `THESADA_QUOTA_DEVICES`, `THESADA_QUOTA_EVENTS_PER_DAY`).
A new user (including a waitlist conversion), a device id the tenant does
not already have (including a reassign into that tenant), and a new alert
are refused at the cap. An update of an existing device still lands, and a
duplicate alert still dedups. Zero turns that one cap off. The admin tenant
list shows count against cap before the refusal.

Source: `pkg/service/quota.go`, `pkg/web/templates/admin-tenants.html`.

### Every read against `pools.App` is tenant-scoped through `db.WithTenant` or explicitly bypassed through `db.WithAdminAudit` **(enforced)**

Shipped. RLS is the steady-state default: `0016_rls_policies.sql`
applies RLS policies to every tenant-scoped table on every deploy. The
`THESADA_APPLY_RLS_POLICIES` env gate was removed once the consumer code
landed - `gatedMigrations` in `migrate.go` is now empty. The
application-layer `WHERE tenant_id = $1` filters remain as the first
line; RLS is the second line of defence.

The refactor wraps every tenant-scoped read in `db.WithTenant`, which
opens a pgx transaction with `SET LOCAL app.tenant_id = $1`. Postgres
RLS policies on every tenant-scoped table then scope rows
automatically. Cross-tenant admin reads (`GetByIDAny`,
`ListAcrossTenants`) go through `db.WithAdminAudit` against
`pools.Admin` (the `BYPASSRLS` role) which writes an audit log row.

How enforced: `scripts/check-pools-app.sh` (wired into
`.github/workflows/ci.yml` as the `pools-app-guard` job) fails any
PR that introduces a new `pools.App.{Query,QueryRow,Exec,Begin,
SendBatch,CopyFrom,BeginTx}` caller outside the grandfathered set in
`scripts/pools-app-allowlist.txt`.

Guard limitation, learned 2026-07-10: the check is textual on
`pools.App.`, so a component that receives the App pool under another
name evades it - `pkg/alerts` queried through its `n.db` field with no
tenant GUC and RLS silently returned zero rows (alert delivery dead -
the silent-drop bug). When handing the App pool to a component, the receiver
either takes tenant IDs and wraps every query in `db.WithTenant`
(what `pkg/alerts` does now, verified by
`pkg/alerts/alerts_integration_test.go`), or it belongs on the
allowlist with a justification.

Phase 2 is complete: every `pkg/service/*.go` file converted to
`db.WithTenant` / `db.WithAdminAudit`. Every `pkg/service` file is now
converted: the last grandfathered entry (`config_snapshot.go`, dead
code) was deleted in phase 3 (migration `0021`), so the allowlist
holds only the structural `pkg/db/` prefix - the helpers themselves wrap
the pool. Phase 3 fixed two bugs in `0016` (the `magic_link_tokens`
policy referenced a non-existent `tenant_id` column; the
`deleted_device_tombstones` table had no policy at all) and added the
acceptance test.

How verified: `pkg/db/rls_integration_test.go` (build tag
`integration`) seeds two tenants and asserts the App and MQTT pools
see only their own rows while the Admin pool sees all. It is not in
the default `make test` lane - run it against a disposable
TimescaleDB with `THESADA_TEST_DATABASE_URL` set; see the file header.

Service-layer tenant scoping is additionally covered by
`pkg/service/*_integration_test.go` (e.g. `DeviceService` cross-tenant
`GetByID` / `ListByTenant` / tombstone isolation), which spin a throwaway
TimescaleDB via `pkg/service/servicetest` and run under `make
test-integration`.

The acceptance test passes and the `THESADA_APPLY_RLS_POLICIES` gate was
removed; `0016` now applies on every deploy (`gatedMigrations` is empty),
making RLS the steady-state default.

Source: `pkg/db/tenant.go` (helpers), `pkg/db/pools.go`,
`migrations/0001_init.sql`, `scripts/check-pools-app.sh`,
`scripts/pools-app-allowlist.txt`, `pkg/db/rls_integration_test.go`.

### Cross-tenant getters are named `*Any` and live behind `RequireSuperAdmin`

Naming convention: every service method that reads outside the
caller's tenant ends in `Any` (e.g. `GetByIDAny`, `ListDevicesAny`).
Every call site is wrapped in `RequireSuperAdmin` middleware. The
naming makes audit-by-grep practical; the middleware enforces.

How enforced: reviewers grep for new `*Any` methods at PR time, check
call site is wrapped. Comments on the service method state the
super-admin requirement.

How verified: `pkg/authmw/authmw_test.go` proves the gate redirects
anonymous callers and 404s non-super users; `pkg/web/routes_test.go`
audits that every gated route (`RequireAuth` + `RequireSuperAdmin`)
actually rejects an anonymous request, catching a handler registered
without its wrapper. The JSON `/api/v1` gates
(`RequireAuthJSON` / `RequireSuperAdminJSON`) return 401/403 instead of a
redirect/404 and are covered by `pkg/authmw/apiauth_test.go`.

Source: `pkg/authmw/` middleware, service files.

### MQTT cross-tenant read default OFF for new tenants

Setting `mqtt_cross_tenant_read` is ON only for the `default` tenant
(homelab legacy layout). Every other tenant defaults OFF - paired
devices get `thesada/<tenant>/#` subscribe scope, never `thesada/#`.

When the admin UI for this setting ships, it must require a second
confirmation, write an audit log entry, and re-pair every device in
the tenant (revoke + reissue dynsec roles) on toggle. Today the
setting is only flippable via direct DB write; the runtime effect is
real on every pair operation.

Source: `pkg/web/admin_pair.go::dynsecSettingCrossTenantRead`,
`pkg/web/admin_pair.go::dynsecDeviceACLs`.

### MQTT topic tenant must match the device's active pairing tenant

Every inbound MQTT message goes through a cross-tenant pairing gate
in `Client.onMessage` before any handler runs: if the
firmware-claimed `device_id` has live (non-revoked, `status='active'`)
certificates, the topic tenant must be one of the tenants holding them,
or the message is dropped without side effects. Broker ACL drift
therefore cannot trick the app into auto-creating a duplicate device row
in the wrong tenant.

The gate accepts any tenant in that set, not only the newest
certificate's. Any account can announce, claim and get a certificate for
a guessable `thesada-<12hex>` id in its own tenant, and a newest-wins
gate let that squat drop the real device's traffic. The squatter's own
certificate only reaches its own tenant's topics through the broker ACL.

A device with no live pairing (never paired, last pairing revoked,
or an issue still mid-push / failed) falls through; the topic tenant
is treated as authoritative until a pairing locks the device into a
specific tenant. The admin "Reassign tenant" flow moves the devices row,
and its certificates with it, so the gate follows the row. It also moves
the device's open WiFi markers and deletes its device-level secrets, which
are bound to the old tenant, so the new tenant provisions them anew. It does not
revoke, and it does not move the broker identity: the dynsec client, its
role and the cert CN keep the tenant they were issued under, which
`devices.broker_tenant_id` records (0040). Older identities still to be
deleted sit in `broker_stale_tenants`. Every teardown (single, bulk and
tenant delete, admin and owner revoke) deletes the names built from the
current and every stale tenant, and forgets each one only once its client is
gone. A failed lookup deletes nothing and raises `dynsec_teardown_failed`.
An unrecorded current identity falls back to the current tenant, unless
another row holds that identity, in which case the row has none and nothing
is deleted. Provisioning reserves the identity before any broker write. A
reserve under a new tenant moves the old identity to the stale list, and it
is deleted, or alerted on, once the new client exists. One device row holds
a current identity (`devices_broker_identity_uniq`), a reserve or claim is
refused while another row holds that identity current or stale, and one
unrevoked cert holds a CN (`device_certificates_live_cn_uniq`). After a
reassign the former tenant can neither claim the id (`ErrBrokerIdentityTaken`)
nor be issued the unit's CN (`ErrCertCNLive`). Reassigned enrolled units
still publish on the old tenant's prefix, which the pairing gate drops in
the new tenant.

0040 runs its data steps as `thesada_app_admin`, because the migrate role
owns these FORCE RLS tables without bypassing RLS and would see no rows.
Tests migrate as that same role shape (`servicetest.BootstrapProdRoles`).

How verified: `pkg/service/certificate_integration_test.go` -
`ActivePairingTenants` discovers every paired tenant cross-tenant, a
second tenant adds to the set, and the set empties once the certs are
revoked. `pkg/mqtt/pairing_gate_integration_test.go` - with a newer
squatter certificate the owner's sensor traffic still lands, and a tenant
with a row but no certificate is still dropped.

Source: `pkg/mqtt/mqtt.go::Client.onMessage`,
`pkg/service/certificate.go::ActivePairingTenants`.

---

## Authentication and sessions

### Session tokens are stored as SHA256, never plaintext

Raw session token returned to the browser in a cookie; only the
sha256 hash is persisted. Lookup is by hash, never by string compare
on the raw token, so a leaked DB does not expose live sessions and
timing on the lookup leaks nothing usable.

Source: `pkg/service/auth.go::CreateSession`, `ValidateSession`.

### API bearer tokens are stored as SHA256, never plaintext

The JSON `/api/v1` surface accepts a bearer token
(`Authorization: Bearer`) alongside the session cookie. Like session
tokens, the raw token is returned once at issue time and only its
sha256 hash is persisted in `api_tokens`; lookup is by hash. A token is
user-bound (no scopes); a revoked (`revoked_at` set) or expired token is
rejected. `APIMiddleware` resolves a bearer token first, then falls back
to the session cookie, and stores the same `*service.Session` in the
request context so the gates and `EffectiveTenantID` work unchanged.
`api_tokens` carries the same transitive RLS policy as `user_sessions`
(`user_id -> users.tenant_id`).

How verified: `pkg/service/api_token_integration_test.go` - issue then
validate returns the owning user, revoke and expire are rejected, and a
cross-tenant `ListTokens` returns nothing (RLS).

Source: `pkg/service/api_token.go`,
`pkg/authmw/apiauth.go::APIMiddleware`,
`migrations/0001_init.sql`.

### The JSON `/api/v1/auth` endpoints do not enumerate users

`POST /auth/login` matches an email across all tenants
(`VerifyPasswordAnyTenant`) and returns the same 401 for an unknown email
as for a wrong password; only on success does it set the session cookie
and mint the bearer token. `POST /auth/signup` always answers 200 whether
or not the email is already on the waitlist. Neither response reveals
whether an account exists - the same posture as the web login/signup.

How verified: `pkg/api/v1/auth_integration_test.go` - an unknown email and
a wrong password both return 401 (indistinguishable), and signup returns
200 + lands a waitlist row.

Source: `pkg/api/v1/auth.go::handleAuthLogin`, `handleAuthSignup`.

### Password and magic-link logins ask for a TOTP code when that account enrolled one

A password match or a consumed magic link against a row with
`users.totp_secret` set does not create a session until the 6-digit code
checks. A password account turns that factor on from Settings: the page
shows the base32 secret as an otpauth link, then stores it after the
code matches. There is no QR image. Single sign-on does not ask: that
provider already authenticated the user, and the local factor is only
for password and magic link.
A time before the Unix epoch uses counter zero. A lookup or secret-decode error is a failed login, not "TOTP is off"
and not "the code was wrong". The JSON login returns `totp_required`
until `code` is present and valid. Magic-link verify returns the same
error plus a `challenge` token, finished at `POST /auth/totp`. The web
login parks a 5-minute challenge cookie and finishes at `POST /login/totp`.
A code signs in once: the accepted time step is stored in
`users.totp_last_step` by a guarded `UPDATE` (only a newer step lands), so a
second login with the same code inside its 90 s window is refused, and of
two parallel finishes on one challenge only one opens a session; a loser
gets `ErrExpired`, never an internal error
(`pkg/service/auth_totp_replay_integration_test.go`).
A web finish that cannot decode the secret returns HTTP 500. An expired
challenge redirects to `/login`. Password and magic-link API calls log
`method` to `challenged`, then `challenged` to `passed` when the code
is in the same request. Finish attempts are capped per IP, and five wrong codes delete that
challenge so a new address cannot reset the count. An empty IP
is not one shared bucket. The challenge and setup cookies set Secure.

How verified: `pkg/totp/totp_test.go` checks the RFC 6238 SHA-1 vectors
and that a corrupt secret is an error. `pkg/service/auth_totp_test.go`
checks that a lookup error is not treated as TOTP off, and that the IP
cap skips an empty address. `pkg/service/auth_totp_integration_test.go`
checks the challenge round trip: a wrong code stays `ErrBadCredentials`,
a good code returns the user and the saved method, and a corrupt secret
is not a wrong code. `pkg/api/v1/auth_totp_integration_test.go` and
`pkg/web/web_totp_integration_test.go` check the HTTP contracts.

Source: `pkg/totp/totp.go`, `pkg/service/auth_totp.go`,
`pkg/web/web_totp.go`, `pkg/web/web_auth.go`, `migrations/0032_user_totp.sql`.

### A passkey is a second factor at the same point as TOTP, never the only one

A password account adds a WebAuthn passkey (a security key or a phone)
from Settings after re-entering its password, and removes one the same
way. The password stays the first factor: passwordless sign-in is out of
scope. A login that matched the password or consumed a magic link
challenges when the account has TOTP or at least one passkey
(`SecondFactors`). The web page offers the key, the code, or both. The
JSON logins cannot run a ceremony, so an account whose only second factor
is a passkey gets `401 passkey_required` there, never a session. Single
sign-on does not ask, as with TOTP.

Ceremony state lives in `passkey_ceremonies` (5-minute TTL, deleted when
taken), keyed by the same pending-challenge token for a login and by a
`passkey_reg` cookie (Path `/settings/passkeys`, SameSite Strict) for an
enroll. An assertion signs the challenge of its own ceremony, an answer
for another challenge fails. A sign count that did not grow is refused
(the library's `CloneWarning`), except that 0 after 0 passes, since synced
passkeys do not count. The counter `UPDATE` is guarded the same way, so
of two parallel assertions only one lands. A refused assertion counts
toward the five tries a challenge allows, and the per-IP cap is the TOTP
one. The relying party ID and origins come from `THESADA_WEBAUTHN_RP_ID`
and `THESADA_WEBAUTHN_ORIGINS`, defaulting from `THESADA_BASE_URL`. A
config the library refuses turns passkeys off with a warning, it does not
stop the boot. A passkey-only account still gets its challenge then, and the
second-factor page says passkeys are off instead of rendering no way on. Both tables are tenant scoped by RLS through `users`.

How verified: `pkg/service/auth_passkey_integration_test.go` runs a
software authenticator (`pkg/webauthntest`) through enroll, login, a
replayed counter, an assertion for another challenge, a duplicate
credential, removal, and RLS between tenants. `pkg/web/web_passkey_integration_test.go`
checks the browser contract including CSRF on the JSON ceremonies, and
`pkg/api/v1/auth_passkey_integration_test.go` that a passkey-only account
gets `passkey_required` on both JSON logins. `pkg/web/cross_tenant_integration_test.go`
covers key removal across tenants.

Source: `pkg/service/auth_passkey.go`, `pkg/web/web_passkey.go`,
`pkg/web/web_totp.go`, `pkg/api/v1/auth.go`, `pkg/config/config.go`,
`migrations/0042_user_passkeys.sql`.

### Password verification is constant-time across account existence

`VerifyPassword` and `VerifyPasswordAnyTenant` run a bcrypt comparison even
when no user (or no stored hash) is found, against a fixed decoy hash
(`dummyPasswordHash`, generated once at `DefaultCost`). Without it the
no-user path returns before any bcrypt call and the timing gap enumerates
valid emails despite the identical 401/error. The any-tenant lookup also
bounds work: it orders candidates by `created_at` and checks at most
`maxLoginCandidates` rows, so a reused email is deterministic (oldest
account wins) and cannot turn one login into an unbounded bcrypt run.

How enforced: reviewers reject a new early `return ErrBadCredentials` on a
no-user/no-hash branch that skips the bcrypt step.

Source: `pkg/service/auth_users.go::VerifyPassword`,
`VerifyPasswordAnyTenant`, `equaliseLoginTiming`, `dummyPasswordHash`.

### `/api/v1` reads are tenant-scoped and redact device secrets

Every `/api/v1/devices*` read resolves the tenant via
`authmw.EffectiveTenantID` and goes through the tenant-scoped service
methods (`GetByID`, `ListByTenant`, telemetry/alerts by device pk), so a
caller only sees their own tenant's rows - a foreign device id returns
404, never 403, so existence does not leak. The device JSON shape
(`deviceResponse`) omits the pairing key, owner id, and mqtt topic prefix.

How verified: `pkg/api/v1/devices_integration_test.go` - a device in
another tenant 404s under the caller's bearer token, and the list
response carries no `pairing_key`.

Source: `pkg/api/v1/devices.go`.

### `/api/v1` alert-subscription writes are scoped to the calling user

`POST /alert-subscriptions` ties the row to the authenticated user
(`u.ID` + `u.TenantID`) and 404s a `device_pk` outside the user's tenant.
`DELETE /alert-subscriptions/{id}` removes by id AND user_id, so a user
cannot delete another user's subscription - a foreign id is a silent
no-op. channel and min_severity are validated to the schema's allowed
values (400), not left to surface as a DB constraint 500. A channel kind
the user has no channel row for (telegram before a chat id is set) is 409
with the kind named, not a 500.

How verified: `pkg/api/v1/alerts_integration_test.go` - bad channel and
bad severity return 400, a foreign device_pk 404s, telegram without a
channel 409s, and the create -> list
-> delete lifecycle round-trips.

Source: `pkg/api/v1/alerts.go`.

### Opening a magic link consumes nothing; the POST signs in

`GET /login/verify?token=` renders a page with a sign-in button and does not
touch the token. Mail scanners open links before the user does, so a GET that
consumed the token would burn it and hand the scanner a session. The button
POSTs the token (CSRF-checked) to `POST /login/verify`, which consumes it.

How verified: `pkg/web/magic_link_integration_test.go`.

Source: `pkg/web/web_auth.go::handleMagicLinkForm`, `handleMagicLinkVerify`.

### Magic-link and password-reset consumption is atomic single-winner

`consumeLinkToken` uses `UPDATE ... RETURNING` with
`WHERE consumed_at IS NULL`. Concurrent consumes of the same token have
at most one winner. The loser gets `ErrNotFound`. `ResetPassword`
consumes the reset token and writes the new password hash in that same
transaction, so a reset token sets at most one password.

How enforced: reviewers grep for new SELECT-then-UPDATE patterns on
magic_link_tokens / password_reset_tokens. New token-consume paths
follow the same pattern.

How verified: `pkg/service/auth_integration_test.go` - login token
consumed twice returns `ErrNotFound` on the second call, an 8-way
concurrent consume of one token yields exactly one winner, and a second
`ResetPassword` with a spent token is refused.
`pkg/web/reset_password_integration_test.go` races 8 POSTs of one reset
link and expects exactly one password change.

Source: `pkg/service/auth_magiclink.go::consumeLinkToken`, `ResetPassword`.

### Session tokens rotate every 4 hours of validation activity

A session token value is valid for at most `sessionRotationInterval`
(4 h) before `ValidateSession` mints a fresh 32-byte token, swaps
`token_hash` atomically, parks the old hash in `previous_token_hash`
for `sessionRotationGrace` (60 s), and pushes a new `Set-Cookie` via
the auth middleware. A stolen cookie therefore has a bounded
effective lifetime: at most one rotation interval after the next
legitimate browser hit, the attacker's copy stops validating.

Concurrency: the rotation `UPDATE` carries `WHERE token_hash = $old`
so only one of N concurrent rotations lands; the losers continue
with the old token and do not set a fresh cookie. The 60 s previous-
hash grace window keeps a parallel in-flight request (XHRs racing
the page load that triggered the rotation) from 401-ing on the
already-replaced token.

How verified: `pkg/service/auth_integration_test.go` - aging
`rotated_at` past the interval makes the next `ValidateSession` mint a
fresh token (`NewToken` set) while the previous hash still validates
within the grace window.

Source: `pkg/service/auth.go::ValidateSession`,
`AuthService::rotateSession`, `pkg/authmw/authmw.go::Middleware`,
`migrations/0001_init.sql`.

### Super-admin rows cannot be deleted through the admin UI

`AuthService.DeleteUser` issues a single predicated `DELETE ... WHERE NOT
is_super_admin`, so a super-admin target is refused atomically with no
separate check a concurrent promote could race; zero rows affected
disambiguates `ErrNotFound` from `ErrSuperAdminProtected`. The guard lives
at the service layer so every caller is covered, not just the admin handler
(which separately blocks deleting your own account). Super rows are
platform-critical.

The `users.tenant_id` FK cascades, so tenant delete guards the same rows.
`TenantService.Delete` refuses a tenant that homes any super-admin with
`ErrTenantHasSuperAdmins`, checked with the tenant's user rows locked so a
racing promote waits. It also refuses the caller's home and effective
tenant. The admin handler runs the same super-admin check before the device
walk, so a tenant that cannot be deleted keeps its devices too.

How verified: `pkg/service/auth_users_integration_test.go` -
`DeleteUser_refuses_superadmin` promotes a user, asserts the delete returns
`ErrSuperAdminProtected`, and confirms the row survives.
`pkg/service/tenant_integration_test.go` - `Delete_refuses_super_admin_tenant`.
`pkg/web/admin_tenant_delete_integration_test.go` -
`TestAdminTenantDelete_KeepsSuperAdminTenants` deletes the operator's own
home while impersonating, and a tenant that homes another super-admin.

Source: `pkg/service/auth_users.go::DeleteUser`, `pkg/service/tenant.go::Delete`, `pkg/web/admin.go`.

### Tenant impersonation requires super-admin, enforced at the service layer

`SetImpersonation` crosses tenant boundaries (it points a session's queries
at another tenant), so a single guarded `UPDATE ... FROM users WHERE
is_super_admin` gates the write on the session owner being a super-admin -
no separate check, so nothing can race a concurrent demote. Zero rows
affected means no such session (`ErrNotFound`) or a non-super one
(`ErrNotSuperAdmin`), disambiguated by an existence probe in the same tx.
The `RequireSuperAdmin` middleware on `/admin/impersonate` is the first
gate; this service guard is the backstop so a future route that forgets the
wrapper cannot grant cross-tenant view.

How verified: `pkg/service/auth_sessions_integration_test.go` -
`impersonation_refused_for_non_superadmin` asserts `ErrNotSuperAdmin` and
that the session's tenant view is unchanged;
`impersonation_unknown_session_not_found` asserts `ErrNotFound`.

Source: `pkg/service/auth_sessions.go::SetImpersonation`,
`pkg/web/admin.go::handleAdminImpersonate`.

---

## Cryptographic material at rest

### CA private key is encrypted on disk when `THESADA_CA_KEY_PASSPHRASE` is set

The internal CA signs every per-device mTLS client certificate, so its
private key is the foundation of multi-tenant device identity. With
`THESADA_CA_KEY_PASSPHRASE` set, the on-disk `ca.key` is a
`THESADA-CAKEY-V1` envelope: AES-256-GCM over a PKCS#8-marshaled
private key, under a scrypt-derived KEK (N=32768, r=8, p=1, 16-byte
salt). The passphrase itself is never persisted by the app - it is
consumed at boot from env and held only in memory.

Plaintext PEM on disk is still supported for back-compat with existing
deployments. When loaded that way, `Bootstrap` returns a
`*PlaintextKey` warning that surfaces as a `slog.Warn` at startup
naming the exposed file path and pointing the operator at the
`thesada-app ca-encrypt` migration subcommand.

This defends against backup-leak / sidecar-volume / cold-disk-theft
threat models. It does NOT defend against a live-process compromise -
the decrypted key sits in memory after boot. The KMS path (server
never sees the private key, signing happens at a remote authenticator)
is the year-two follow-up scoped in `docs/security.md`.

Source: `pkg/pki/ca.go::Bootstrap`, `pkg/pki/encrypt.go`,
`pkg/pki/encrypt_test.go`, `cmd/thesada-app/main.go` (warning surface
+ `ca-encrypt` subcommand).

### Device-config secrets are envelope-encrypted under a per-tenant DEK; the operator never reads them back

The 5 sensitive device-config fields (`wifi.password`, `mqtt.password`,
`telegram.bot_token`, `web.password`, `wifi.ap_password`) are stored in a
separate encrypted store (`device_config_secrets`), never in
`device_files` and never as plaintext columns. Envelope encryption
(`pkg/secrets`, AES-256-GCM throughout): the deployment root KEK
(`THESADA_DEVICE_CONFIG_KEK`, 32 bytes, env-sourced, never in the DB)
wraps a per-tenant random DEK (`tenant_dek`); the DEK encrypts each
value. Every ciphertext is AAD-bound - the DEK to its `tenant_id`, each
value to `tenant/device/field` - so a DB-write attacker cannot relocate
one row's ciphertext onto another tenant, device, or field and have it
decrypt.

Write-only contract: `SetSecret` writes, `Status` returns set/unset
booleans only, and there is no operator-facing read-back path. The
server CAN decrypt (`SecretService.Reveal`, `RevealTenantSecret`,
`Resolve`) to provision a device at pair or rotate keys, but those
methods are server-side only and must never be wired to an
operator-facing route - the whole contract depends on them staying off
the request surface.

Two levels, one table: a row with `device_pk` NULL is the **tenant
default** for that field, a row with a `device_pk` is that device's
**override**. Both live in `device_config_secrets` under one partial
unique index each, so the level is a property of the row, not of a
second table. The effective value is `device override ?? tenant
default`, resolved by `SecretService.Resolve` in a single query whose
`ORDER BY device_pk IS NULL LIMIT 1` makes precedence a SQL fact rather
than a two-read race. `Reveal` stays exact-row and does NOT fall back,
so a caller that means "this device's own value" still gets exactly
that. Provisioning (pair-time and both provision buttons) reads through
`Resolve`, which is what lets a device pair into a site whose secrets
are already set without any per-device write.

Tenant-default ciphertext is AAD-bound to `tenant/"tenant-default"/field`
rather than to a nil device UUID, so a default's blob can never be
relocated onto a device row (or the reverse) and still decrypt. Rotating
a default is one write plus a fan-out; devices with an override are
excluded from that fan-out by `ProvisionTargets`, and each target is checked
again under the device row lock right before its push, so a pinned device is
never quietly re-pointed by a tenant-level rotation.

The legacy bare `wifi.password` names no network. A current device read
re-keys a device's bare row once to `wifi.password:<primary SSID>` of that
read: decrypt under the old AAD, encrypt under the new one, delete the bare
row, in one tx under the device row lock. When the `config.json` the app
held before that read names another primary SSID, the bare row is deleted
instead, audited as `device_secret.legacy_wifi_dropped` (field name only),
and the operator enters the new network's password. `thesada-app migrate-legacy-wifi`
does the same from each device's stored `config.json`. When a per-SSID row
for the primary already exists it wins and the bare row is deleted, logged
with device and field. A bare row left behind (no SSID known, or it does not
decrypt) is inert: not provisioned, not counted by reads or
`ProvisionTargets` / `ProvisionTargetCounts`, listed on the secrets page for
Clear. `SetSecret` and `SetTenantSecret` refuse the bare field, and `Resolve`
never inherits a bare tenant row planted by an older build or by SQL.
Tenant WiFi defaults are always per-SSID, and the operator names the network
on the tenant page rather than typing a storage key.

Config hygiene: the write path never persists plaintext secrets in
`device_files` / `device_file_history` (legacy pre-backfill
`device_file_history` rows may still hold plaintext - see Residual).
`DeviceFilesService.Upsert` is the single
chokepoint every ingest + app-write path funnels through; for
`config.json` it blanks the sensitive leaves (`blankConfigSecrets`:
the `SecretFields` allowlist plus a `sensitiveConfigKeyRE` backstop)
before the row is written. The device-reported `sha256` is kept as-is
as the drift fingerprint - blanking changes only the stored content, so
a sanitized snapshot never reads as drift against the device. Clean
configs (already-blank, e.g. app-managed devices) pass through
byte-identical.

Tenant delete crypto-shreds: the `tenant_dek` row cascades away on
`tenants` delete, rendering that tenant's ciphertext permanently
unrecoverable regardless of what backups still hold the `device_config_secrets`
rows. Root-KEK rotation re-wraps DEKs (phase 7), never re-encrypts values.

Both new tables are RLS `FORCE`d: `tenant_dek` scopes directly on
`tenant_id = app_tenant_id()`; `device_config_secrets` scopes reads on
its denormalized `tenant_id` and its write `WITH CHECK` additionally
binds `device_pk` to the calling tenant (an `EXISTS` against `devices`),
so a cross-tenant `device_pk` is rejected at write - the AAD binding is
the second line, RLS the first.

Feature gate: an empty `THESADA_DEVICE_CONFIG_KEK` leaves the feature
off (devices keep plaintext config); a non-empty but malformed KEK is a
hard boot failure (`NewSecretService` -> `service.New` error ->
`os.Exit`), never a silent fallback to off. The root KEK must never be
rendered: the `/admin/debug` redactor masks by trailing token, so KEK
config fields are named to END in `KEK` and `sensitiveKeyRE` includes
`kek` (a field named `...KEKNew` would print in cleartext - a bug caught
in review). Rotation is idempotent + re-runnable (`RotateRootKEK` retries
each DEK under the new key and skips already-rotated rows) so the operator
can re-run until `rotated=0` and no swap-window DEK is orphaned.

Provisioning + field keys: `SecretFields` are the firmware `secret.set`
keys (the firmware keymap) so a paired device is provisioned by
`handleAdminDevicePairIssue` pushing `secret.set <field>\n<value>` to
NVS (mirror of `cert.set`, before the restart, feature-gated). Four map
1:1; `wifi.password` is per-SSID on the firmware, so it is provisioned as
`wifi.password:<ssid>` (`FirmwareSecretField`), resolving the SSID from
the device's stored config. Root-KEK rotation (`rotate-kek` /
`RotateRootKEK`) re-wraps every DEK under a new KEK in one admin tx and
never touches value ciphertext. Existing devices migrate via
`backfill-secrets` (`BackfillDeviceSecrets`): extract plaintext from the
stored config, `SetSecret`, re-blank. KEK-in-env is v1; KMS is the later
follow-up. Residual: backfill does not purge plaintext from older
`device_file_history` rows.

How verified: `pkg/secrets/secrets_test.go` (crypto core: round-trip,
tamper / wrong-key / wrong-AAD reject, nonce freshness),
`pkg/service/secret_integration_test.go` (DB round-trip, overwrite,
write-only Status, cross-tenant RLS isolation, feature-off gate,
malformed-KEK boot failure), `pkg/service/tenant_integration_test.go`
(`Create_provisions_tenant_DEK`, `Delete_crypto_shreds_secrets`),
`pkg/service/config_secrets_blank_test.go` (allowlist + backstop + clean
passthrough + extract inverse), `pkg/service/device_files_integration_test.go`
(`config_json_secrets_blanked_sha_preserved`),
`pkg/service/secret_phase7_integration_test.go` (rotation: old-key-fails /
new-key-works / kek_version bump; backfill: extract -> encrypt -> re-blank,
idempotent), `pkg/service/secret_fields_test.go` (`FirmwareSecretField`
mapping), `pkg/web/provision_test.go` (pair-time provision loop:
ordering, skip-unset, no-SSID skip, reveal-error + push-fail abort),
`pkg/web/admin_secrets_integration_test.go` (write-only POST stores +
round-trips, rejects empty/unknown),
`pkg/service/secret_tenant_integration_test.go` (precedence: inherit,
override wins, override survives a default rotation, clear falls back,
cross-tenant default isolation, tenant-vs-device AAD not interchangeable,
`ProvisionTargets` excludes overridden and unpaired devices), and the web
auth-gate + bad-UUID audits for the two secrets routes (`routes_test.go`,
`handler_input_test.go`). Residual: the thin handler-to-MQTT adapter in
`handleAdminDevicePairIssue` (the closures wiring Reveal/pushSecret into
the tested loop) has no end-to-end pairing test - it needs an MQTT device
sim. The tenant-secret HTTP handlers
(`pkg/web/admin_tenant_secrets.go`) are likewise untested at the handler
level; the fan-out counting and the redirect messages rest on the
service-level tests underneath them.

Source: `pkg/secrets/secrets.go`, `pkg/service/secret.go`
(`SecretFields`, `FirmwareSecretField`, `Reveal`, `RotateRootKEK`),
`pkg/service/tenant.go` (`Create` DEK provisioning),
`pkg/service/config_secrets_blank.go`, `pkg/service/secret_backfill.go`,
`pkg/service/device_files.go` (`Upsert` blanking chokepoint),
`pkg/web/admin_pair.go` (`pushSecret` provisioning),
`pkg/web/admin_secrets.go` (write-only UI),
`migrations/0023_device_config_secrets.sql`, `pkg/config/config.go`
(`DeviceConfigKEK` + `_NEW`), `cmd/thesada-app/main.go`
(`service.New` error surface, `backfill-secrets` + `rotate-kek`),
`docs/security.md` (operator runbook).

### Device WiFi credentials: one state model over NVS, config.json and the app store

The firmware resolves every secret from NVS first and falls back to
`config.json` only when NVS is empty, and `secret.set <field> ""` clears
NVS. So `config.json` is not the device's effective secret: the app store
mirrors NVS, an open marker describes the file, and the write guard asks
the device about NVS live (C1, #99, Q1 to Q6 of the 2026-11-18 design pass).

Facts, one per place:

| Place | Fact the app holds | Written by | Current when |
|---|---|---|---|
| Device NVS | nothing stored. Asked live through `secret.info` | provisioning (`secret.set`), Clear on device | the correlated `secret.info` answer of this request |
| Device `config.json` | an open marker in `device_open_networks` (device, SSID, `seen_at`, source) per SSID whose password the file holds as `""`, plus the blanked snapshot | a current device read: drift pull, CLI box `config.dump`, Load from device, a confirmed write | `seen_at` newer than `devices.config_changed_at` |
| App store `device_config_secrets` | a device override or a tenant default per `wifi.password:<ssid>`, never `""` | Set on the secrets page, gap fill from a read, legacy re-key | always. It is what provisioning sends |

Transitions:

| Event | NVS | `config.json` fact | App store |
|---|---|---|---|
| Current device read | unchanged | markers replaced by exactly the read's `""` SSIDs, whatever the store holds | gap fill only for a field with no device row and no tenant default. A bare legacy row is re-keyed to the read's primary SSID first, or dropped when the stored `config.json` names another primary SSID. Markers are recorded with the store off too |
| Stale read (started at or before `config_changed_at` or before `config_read_at`) | unchanged | nothing written | nothing written |
| Set on the secrets page | unchanged until provisioned | unchanged | device row upserted. `""` and the bare `wifi.password` refused |
| Provision (pair, Provision to device, tenant rotation) | `secret.set` per resolved value, never `""` | unchanged | unchanged. Provision to device then checks `secret.info` |
| Clear on device, verified | field cleared | unchanged | the device's row for the field dropped, and the bare legacy row unless a stored `config.json` names another primary SSID (no stored config, or one that names no network, drops it too, logged `device_secret.legacy_wifi_cleared` with `reason: no stored config` or `no primary ssid`), in one tx under the device row lock. The per-SSID row and the bare legacy row are read before the clear, in one tx under the device row lock that ends before the device is asked. A per-SSID row that differs at drop time (a password saved meanwhile, the same password too, as every write seals with a fresh nonce) is kept, flashed `nvs_cleared_store_replaced` and audited `store_replaced: true`. A per-SSID row that was absent at the mark, beside a marked bare row, and still carries `rekeyed` is the re-key of that bare row and is dropped, flashed `cleared` and audited `store_dropped: true`. No value is decrypted or compared for that. A failed drop is flashed and audited `store_dropped: false` |
| Clear on device over a tenant default | refused, nothing sent | unchanged | unchanged |
| Clear (override) on the secrets page | unchanged | unchanged | device row deleted, the device falls back to the tenant default |
| `config.json` write, config-changing CLI command, rename | maybe changed | `config_changed_at` stamped, every marker stale until a newer read. A confirmed write refreshes as a read | a confirmed write refreshes as a read |
| SSID change on the device | unchanged | the next current read marks the new set | rows stay under their own SSID. A bare row moves once, to an unchanged primary only. A new primary drops it |
| `migrate-legacy-wifi` | unchanged | unchanged | each bare row re-keyed to the stored config's primary SSID, dropped beside an existing per-SSID row, else left inert |
| Device reassign | unchanged | markers move to the new tenant | device-level secrets deleted (AAD-bound to the old tenant) |

Rules:

| Rule | Why |
|---|---|
| A device read stores a secret only for a field the store has nothing for: no device row and no tenant default the device inherits | a stale plaintext or an explicit `""` in `config.json` must never replace the value NVS holds. A device on the tenant default stays inherited |
| `device_config_secrets` never holds `""`: `SetSecret` and `SetTenantSecret` return `ErrEmptySecret`, and a CHECK refuses a 28-byte blob (the AES-GCM sealing of nothing) | an empty value used to count as an override, so tenant rotation skipped the device and provisioning pushed the empty value |
| A marker is a fact about the file only. `SetSecret`, provisioning and Clear on device never touch markers | what NVS holds is the guard's own question, asked at write time |
| The `config.json` write guard passes an empty WiFi password only for a current marker and a correlated `secret.info` reporting nothing in NVS for that field. It passes an empty scalar secret (`mqtt.password`, `telegram.bot_token`, `web.password`, `wifi.ap_password`) only when a correlated `secret.info` reports it in NVS. One `secret.info` per guard run. NVS holding a WiFi password, a scalar not in NVS, `secret.info` failing, answering without the `req_id` or not telling two SSIDs apart refuses with its own message naming the field. `null` counts as empty. An empty sensitive leaf the store has no field for (`cellular.sim_pin`, `lora.meshtastic.psk`) is refused by its path, since nothing on the device can be asked about it. The guard works the same with the KEK unset | the marker describes the file the write replaces, NVS is what the firmware reads first, so an empty scalar beside an NVS value changes nothing on the device |
| The guard runs at enqueue and again in the worker under the claim, right before the first chunk, each time with its own `secret.info`. A marker lookup has a 10 s deadline, `secret.info` 5 s, and the worker renews its claim after the guard or sends nothing | a marker can go stale and NVS can gain a password while a write waits, and a stalled lookup must not let a second write take the device |
| `config_changed_at` is set by every `config.json` write (after the write-time guard and before the first chunk, nothing is sent when that fails, and again once the rename is confirmed, before its own refresh), every config-changing CLI command (before it is sent and again after it answers) and a failed or unknown rename. The mark before sending stamps now plus the claim's lifetime, the later marks stamp now | a write whose refresh then fails still leaves every older marker stale, and a read of the old file during the change stays stale when the mark after it fails, so the guard fails closed |
| A device read carries its start, taken from the database clock before the request goes out. A stale read writes nothing, is logged as `device.read.stale_dropped`, and `UpsertFromDevice` reports it not stored (nil error), so the drift pull logs `device_file saved` only for a stored snapshot | the check, the legacy re-key, the gap fill, the markers and the snapshot run in one transaction under `SELECT ... FOR UPDATE` on the device row, so a change cannot land between them, and a refresh that fails part way rolls back whole |
| A failed store after a confirmed `config.json` write marks the request failed. For any other file the snapshot row is not load-bearing: the failure is logged and the write stands, so the rules push still reloads | the guard depends on the `config.json` refresh, nothing depends on a script snapshot |
| A config-changing CLI command (`config.*` apart from `config.dump`, `fs.format`, `ota.*` apart from `ota.status` as a firmware update can migrate the file, any `fs.*` naming `config.json` or holding `*` or `?`, since a glob in a `/.` directory reaches past the firmware's root skip) takes the device write claim, 409 while a write holds it | a staged write that already passed the guard cannot be overtaken by a command that sets a password |
| The bare legacy `wifi.password` row is re-keyed once to `wifi.password:<primary SSID>`: decrypt under the old AAD, encrypt under the new one with `rekeyed = true`, delete the bare row, in one tx under the device row lock. Every other write of a device row (Set, gap fill) stores `rekeyed = false`, so the flag means the re-key wrote the row and nothing since (0049, rows before it read false). A per-SSID row already there wins and the bare row is deleted, logged with device and field. When the stored `config.json` (the snapshot before this read or confirmed write) names a primary SSID other than the read's, the bare row is deleted and audited `device_secret.legacy_wifi_dropped`, never re-keyed. Blind spot: the bare row carries no SSID, so a primary that changed before the first snapshot the app holds, or changed and changed back between two reads, reads as unchanged. No stored snapshot, or one that names no network, also re-keys. A tenant default for that network does not count as such a row: the legacy value becomes a device override, so the store matches what the device holds, and later tenant rotations of that network skip the device until the override is removed. A bare row left (no SSID known, or it does not decrypt) is inert: not provisioned, not read, no override in `ProvisionTargets` / `ProvisionTargetCounts`, listed on the secrets page for Clear, refused by Clear on device | the bare key names no network, and three operations each used to infer one |
| Provisioning never sends an empty or unset value, and `pushSecret` refuses `""` itself | `secret.set <field> ""` clears NVS and can take a remote device off WiFi |
| A tenant default fan-out checks each target for an override again at push time, holding the device row lock across the check and the push (`PushUnlessOverridden`). A device overridden since `ProvisionTargets` is skipped and counted `overridden`, not `pushed`. Each target runs under its own `fanOutPerDeviceBudget` (15 s) for the lock wait and the push, so a device stuck on its row lock is counted `skipped` alone and the sweep goes on | `SetSecret` takes the same lock, so an override cannot land between the check and the push and be overwritten in NVS by the default |
| Clear on device is its own action on the secrets page, behind a confirm, only with the store on, audited as `device_secret.clear_nvs` with `verified`, `store_dropped` and `store_replaced`. A field without blanks goes as `secret.clear <field>`, and only its `secret cleared` line counts. A field whose SSID holds a blank goes as binary `secret.set` with an empty value (`Secret::set` clears on empty), then `secret.info` must not report it in NVS. An unverified, uncorrelated or failed clear keeps the row. A WiFi password that resolves to a tenant default is refused before anything is sent: set a device override or clear the tenant default first | the device shell splits `secret.clear` on blanks, every `secret.set` reply says stored, a clear too, and a tenant default has no device row to drop and comes back on the next provision |
| After Provision to device the app reads `secret.info` and reports every pushed field the device does not hold in NVS. No answer, an uncorrelated answer, a key the report repeats, or two fields one key stands for (SSIDs that differ only by trailing blanks) are reported as not verified | every transport answers `secret stored in NVS`, also for a clear |
| A device reassign moves its open markers to the new tenant and deletes its device-level secrets, in the same admin transaction. A reassign to the device's own tenant writes nothing | rows tagged with the old tenant would make every later read for the device fail under RLS, and the secrets are AAD-bound to the old tenant. The new tenant provisions anew |

Every device reply in this model that feeds a stored fact needs the echoed
`req_id`, see "A stored device reply echoes its request id" above.

The order lives in the database, so a restart or a second app instance
sees it. Gap fill and the legacy re-key need the store (KEK set). Without
a KEK the store is off, markers are still recorded, the guard still asks
the device, snapshots are still blanked and stale reads are still dropped. Not covered:
pair and tenant rotation trust the `secret.set` reply and do not read
`secret.info`, a write can still land an empty password for a network a
drift pull saw locked after the guard ran, and a device whose bare row no
read or sweep has re-keyed yet provisions no WiFi password until one does.

How verified, per cell:

| Cell | Tests |
|---|---|
| Current read: gap fill, markers, re-key | `pkg/service/device_files_secrets_integration_test.go` (`a_read_fills_gaps_and_records_open_networks`, `an_empty_or_stale_password_never_overwrites_a_stored_one`, `an_empty_password_is_marked_open_whatever_the_store_holds`, `tenant_default_stays_inherited`, `a_password_in_a_current_read_clears_the_marker`, `a_legacy_password_is_rekeyed_to_the_primary_ssid`, `a_failed_refresh_rolls_back_whole`, `feature_off_still_blanks_and_orders`), `TestLegacyWifi/a_read_with_the_stored_primary_rekeys_it`, `TestLegacyWifi/a_new_primary_drops_the_bare_row_drift`, `TestLegacyWifi/a_new_primary_drops_the_bare_row_write` |
| Stale read | `a_stale_read_writes_nothing`, `TestBrokerDriftStaleReadLogsNoSave`, `an_older_read_after_a_newer_one_is_dropped`, `a_marker_older_than_a_config_change_does_not_count`, `a_new_service_instance_still_refuses_a_stale_marker`, `TestLegacyWifi/a_stale_read_rekeys_nothing` |
| Set | `set_secret_does_not_change_the_file_fact`, `set_secret_beside_a_read_does_not_deadlock`, `an_empty_value_is_not_a_secret`, `TestLegacyWifi/set_secret_refuses_the_bare_field` |
| Guard | `pkg/web/open_wifi_guard_integration_test.go` (`guard_passes_when_secret_info_reports_nothing_in_nvs`, `guard_refuses_when_nvs_holds_a_password`, `guard_refuses_when_secret_info_is_uncorrelated`, `guard_refuses_when_secret_info_fails`, `a_password_provisioned_after_the_open_read_is_refused_at_write_time`), `pkg/web/admin_config_integration_test.go` (`TestAdminConfigWrite_GuardRunsAgainAtWriteTime`, `TestAdminConfigWrite_StaleMarkerRefusedAfterRestart`, `TestAdminConfigLoad_RefreshesMarkers`), `pkg/web/admin_config_blank_integration_test.go` (`TestBlankSecretGuard_Scalars`, `TestBlankSecretGuard_StoreOff`), `pkg/web/admin_config_restore_test.go`, `pkg/service/config_secrets_blank_test.go` (`TestSensitiveConfigKey`, `TestBlankSecretFields_NullIsEmpty`) |
| Write, CLI command, rename | `TestAdminConfigWrite_RefreshesTheSecretStore`, `TestAdminConfigCmd_ConfigRenameMakesMarkersStale`, `TestAdminConfigCmd_ConfigChangeIs409WhileAWriteRuns`, `TestAdminConfigWrite_UnknownRenameMarksConfigChanged`, `TestAdminConfigWrite_MarksChangeBeforeSending`, `TestAdminConfigWrite_FailedMarkAfterRenameKeepsMarkersStale`, `TestAdminConfigWrite_SnapshotFailureKeepsOtherWrites` |
| Provision | `pkg/web/provision_test.go`, `TestAdminDeviceSecretsProvision_Integration`, `pkg/web/tenant_fanout_override_integration_test.go` (`an_override_after_the_target_list_is_skipped`, `an_override_write_waits_for_a_running_push`, `TestTenantFanOutDeviceBudget`) |
| Clear on device | `TestAdminDeviceSecretsClearDevice`, `TestAdminDeviceSecretsClearDevice_DropsWifiRow`, `pkg/web/clear_on_device_integration_test.go` (`a_tenant_default_password_is_refused`, `an_override_over_a_tenant_default_is_cleared_and_dropped`, `a_failed_row_drop_is_reported`, `a_password_saved_during_the_clear_survives`), `TestLegacyWifi/a_password_saved_after_the_mark_is_kept`, `TestLegacyWifi/a_rekey_during_the_clear_is_dropped`, `TestLegacyWifi/a_rekey_then_a_new_save_during_the_clear_keeps_the_save`, `TestLegacyWifi/a_rekey_then_a_same_value_save_during_the_clear_keeps_the_save`, `TestLegacyWifi/a_same_value_save_then_a_rekey_during_the_clear_keeps_the_save`, `TestLegacyWifi/a_same_value_resave_of_the_marked_row_is_kept`, `TestLegacyWifi/the_mark_reads_both_rows_under_the_device_lock`, `TestLegacyWifi/without_a_legacy_row_a_clear_drops_and_a_save_is_kept`, `TestLegacyWifi/a_verified_clear_of_the_primary_drops_the_bare_row_too`, `TestLegacyWifi/a_verified_clear_without_a_stored_config_drops_the_bare_row`, `TestLegacyWifi/a_verified_clear_with_no_networks_stored_drops_the_bare_row`, `TestLegacyWifi/a_verified_clear_of_another_network_keeps_the_bare_row` |
| Legacy re-key and sweep | `pkg/service/legacy_wifi_integration_test.go` (`TestLegacyWifi`, `TestLegacyWifi/only_the_rekey_marks_its_row`, `TestLegacyWifiSweep`: with and without a snapshot, with and without a per-SSID row, flagged, idempotent), `migrations/secret_rekeyed_integration_test.go` (`TestMigration0049_RekeyedFlag`), `pkg/service/secret_tenant_integration_test.go` (`a_bare_device_row_is_not_an_override_for_a_per_SSID_default`, `a_planted_bare_tenant_default_is_never_inherited`) |
| Reassign | `a_reassign_to_the_same_tenant_keeps_device_secrets`, `a_read_after_a_reassign_stores_under_the_new_tenant`, `migrations/open_networks_integration_test.go` |

Source: `pkg/service/device_config_state.go`, `pkg/service/secret.go`,
`pkg/service/secret_legacy_wifi.go`, `pkg/web/admin_config.go`,
`pkg/web/admin_pair.go`, `pkg/web/admin_secrets.go`,
`pkg/mqtt/mqtt_snapshot.go`, `migrations/0048_device_open_networks.sql`.

### Passwords use bcrypt at default cost (10)

`bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)`. No
SHA256-then-bcrypt, no length cap workaround, no custom KDF.

Source: `pkg/service/auth.go::SetPassword`.

### The password floor lives in `SetPassword`, not just the handlers

`SetPassword` rejects anything under `MinPasswordLen` (10) with
`ErrPasswordTooShort` before hashing, so the floor holds for any caller -
the settings form, the reset flow, and any future path. The two handlers
keep a friendlier inline message but reuse the same `service.MinPasswordLen`
constant rather than a literal, so the floor has one source of truth.

How verified: `pkg/service/auth_users_integration_test.go` -
`SetPassword_rejects_below_floor` asserts a 9-char password returns
`ErrPasswordTooShort`, nothing is stored, and a 10-char password is accepted.

Source: `pkg/service/auth_users.go::SetPassword`,
`pkg/service/auth.go::MinPasswordLen`, `pkg/web/web_settings.go`,
`pkg/web/web_auth.go`.

---

## CSRF

### Every state-changing HTTP endpoint requires CSRF verification

Signed double-submit cookie pattern: server sets an HttpOnly cookie
`thesada_csrf` whose value is a random token plus an HMAC-SHA256 signature
under the app's cookie secret (`<body>.<sig>`); the client reflects the
exact value via header `X-CSRF-Token` or hidden form field. Middleware
verifies unsafe methods (`{POST, PUT, PATCH, DELETE}`) echo the cookie,
constant-time. The signature is what lifts this above plain double-submit:
a sibling subdomain (or anything that can plant a cookie but does not hold
the secret) cannot forge a value that passes the signature check, so
`ensureCookie` discards the planted cookie and mints a fresh one - the
attacker's submitted value then no longer matches and the request 403s.

How enforced: middleware `pkg/csrf` runs on every router group that
isn't explicitly read-only (wired with `cfg.CookieSecret` in
`pkg/web/web.go`). Reviewers check new mutating endpoints sit behind it.

Deploy note: an old unsigned cookie fails the signature check, so a form
loaded before this shipped and submitted after will 403 once; `ensureCookie`
replaces the cookie on that same response and a refresh recovers.

How verified: `pkg/csrf/csrf_test.go` -
`TestMiddleware_RejectsPlantedCookie` (an unsigned planted cookie is
refused), `TestValidToken_AcceptsMintedRejectsForged` (only secret-signed
values validate), plus the missing/mismatched-token 403 paths.

The unauthenticated JSON auth endpoints under `/api/v1/auth` (login,
magic-link, magic-link/verify, totp, signup) carry no CSRF token. They
answer 415 unless the body is declared `application/json`, a type a
cross-site form cannot send without a CORS preflight. Without that, a
`text/plain` form could sign the victim's browser into the attacker's
account. Verified by `pkg/api/v1/auth_csrf_integration_test.go`.

Source: `pkg/csrf/csrf.go`, `pkg/web/web.go`, `pkg/api/v1/api.go::requireJSON`.

---

## OAuth

### OAuth flow uses PKCE S256 + nonce + state, single-use state via DELETE-RETURNING

Every authorize request generates a PKCE code verifier (S256
challenge), a nonce, and a state value persisted to
`oauth_auth_requests`. On callback, the row is deleted with
`RETURNING` so reuse fails atomically. PKCE is required for
confidential clients - non-negotiable.

`/start` also sets the state in an HttpOnly, Lax, Secure host-only cookie
`__Host-thesada_oidc_state` (Path=/, no Domain, so a sibling host cannot
plant one), and the callback refuses a
state that cookie does not carry, before the state row is touched. A
callback URL from the attacker's own IdP login therefore does not sign
another browser in. Verified by `pkg/web/oidc_state_integration_test.go`.

Source: `pkg/service/oauth.go`, `pkg/web/oauth.go`.

### Every OAuth redirect target passes through `IsSafeReturnTo`

Open-redirect prevention. `return_to` query parameters and stored
post-login redirects are checked for same-origin + path-only before
issuing a 302. Centralised so any new redirect site picks up the
check by default.

How verified: `pkg/web/oauth_test.go::TestSafeReturn` - pass-through
for vetted relative paths, fallback for absolute / scheme-relative
(`//`) / non-slash input.

Source: `pkg/oauth/oauth.go::IsSafeReturnTo`, wrapped by
`pkg/web/oauth.go::safeReturn`.

### OIDC callback loads the provider by stored id, never re-resolves by slug

`/start` records the chosen provider's id in the auth request
(`pending.ProviderID`). The callback MUST load that exact provider via
`LoadProviderByID`, not `LoadProviderBySlug`. Re-resolving by slug with an
empty tenant hint returns `ORDER BY id LIMIT 1` - the lowest-id tenant's
provider - so any session on a different tenant gets a provider mismatch and a
400. Loading by stored id keeps `/start` and `/callback` symmetric per tenant.

Source: `pkg/web/oauth.go::handleOIDCCallback`, `pkg/service/oauth.go::LoadProviderByID`.

### Email auto-link is scoped to the provider's tenant

When the callback finds no existing (provider, subject) link but the id_token
carries a verified email, it may auto-link to a local user - but
`FindUserByEmail` matches only within the provider's own tenant. Email is
unique per `(tenant_id, email)`, so an unscoped match could bind the session to
the wrong tenant's user when the same address exists in several tenants. A
global provider (`tenant_id` NULL) has no tenant to scope to and therefore never
auto-links by email; those users link manually from settings. Successful
auto-links log `oauth.identity.state_change` (trigger `email_match`).

Source: `pkg/service/oauth.go::FindUserByEmail`, `pkg/web/oauth.go::handleOIDCCallback`.

---

## SQL and templating

### All SQL is parameterized

No `fmt.Sprintf` into a SQL string anywhere. pgx parameter binding
only. Reviewers grep for `fmt.Sprintf` near `Query` / `Exec` /
`QueryRow` at PR time.

### HTML rendered via `html/template`, plain text via `text/template`

`html/template` auto-escapes by default; `text/template` does not.
The two are not interchangeable - using `text/template` for HTML
output is an XSS vector. Email bodies are the only `text/template`
consumers, and even there only for plain-text MIME parts (HTML mail
templates use `html/template`).

Source: `pkg/web/templates/`, `pkg/service/mailer.go`.

### A page is sent only after its template ran to the end

`renderStatus` executes the page into a buffer. A template error answers a
plain 500 with nothing of the half page, and a good render sets
`Content-Type: text/html; charset=utf-8` before its status, so a 400 or
429 page is still HTML. Handlers pass the status to `renderStatus` and
never call `WriteHeader` before a render.

Source: `pkg/web/web.go::renderStatus`, `render_test.go`.

### Templates carry no inline event handlers

The CSP allows only nonced scripts (`script-src 'self' 'nonce-...'`), so
an `onclick`, `onsubmit` or `onchange` attribute never runs: a confirm is
skipped and a toggle saves nothing. A form asks with `data-confirm`, a
field submits its form with `data-autosubmit`, a button calls a page
function with `data-act` / `data-arg`, and the nonced layout script
handles all of them.

How verified: `TestTemplatesCarryNoInlineHandlers` scans every template,
`TestLayoutFormListenersAutosubmitAndConfirm` runs the layout listeners
under node.

Source: `pkg/httpsec/headers.go`, `pkg/web/templates/layout.html`.

### Migrations are forward-only and idempotent

`migrations.Apply` runs every `*.sql` newer than the highest version in
`schema_migrations`, each in its own transaction, recording the version
on success. There are no down migrations - rollback is a new
forward migration. Re-running `Apply` on an up-to-date database is a
clean no-op; a migration that is not safely re-runnable (e.g. a `CREATE`
missing `IF NOT EXISTS`) is the failure this guards against.

How verified: `migrations/migrate_integration_test.go` (build tag
`integration`) applies all migrations to a fresh TimescaleDB container,
then applies again and asserts `schema_migrations` is unchanged.
Run with `make test-integration`.

Source: `migrations/migrate.go::Apply`.

---

## Cookies

### Session + CSRF cookies: SameSite=Lax + Secure-when-HTTPS

Session cookie set via `authmw.SetSessionCookie` (login in
`pkg/web/web.go::startSession` and rotation in `pkg/authmw`); CSRF cookie in
`pkg/csrf`. All decide the Secure flag through the one shared
`httpsec.RequestIsSecure(r, trustedProxies)` - true when `r.TLS != nil`, OR
the immediate peer is in `THESADA_TRUSTED_PROXIES` and set
`X-Forwarded-Proto: https`. The trusted-peer gate is the same one `ClientIP`
uses: an arbitrary peer cannot spoof the header to get Secure-flagged
cookies (or HSTS) over plain HTTP. Correct behind HAProxy (TLS to the
browser, plain HTTP to the app, proxy listed in trusted proxies); dev
(plain HTTP, direct) still works without config drift.

### Session and CSRF cookies are both HttpOnly

Nothing reads either cookie client-side: the CSRF token reaches JS through
the `CSRFToken` template variable, and the double-submit check compares the
echoed header/form value against the cookie server-side. Same SameSite=Lax
+ the shared Secure decision above.

Source: `pkg/csrf/csrf.go`, `pkg/web/web.go`, `pkg/authmw`, `pkg/httpsec`.

### The cookie secret must be >= 32 bytes; short secrets hard-fail at boot

`THESADA_COOKIE_SECRET` signs both the session cookies and (now) the CSRF
tokens, so a weak secret undermines both. `config.validate` aborts startup
when it is under `minCookieSecretLen` (32) unless `THESADA_ALLOW_WEAK_SECRET`
is set truthy - safe by default, with an explicit, logged escape hatch for
an existing sub-32-byte deployment to boot across a restart while it rotates.
The error names the override so an operator hitting it knows the way out.

How verified: `pkg/config/config_test.go::TestValidate_CookieSecretFloor`
(empty/weak/weak+override/strong matrix) and
`TestValidate_WeakSecretErrorIsActionable`.

Source: `pkg/config/config.go::validate`, `minCookieSecretLen`, `envBool`.

---

## WebSocket origin

### Upgrades validate Origin against BaseURL

Both the device-event hub (`pkg/ws`) and the admin MQTT shell
(`pkg/web/admin_mqtt.go`) reject a cross-origin WebSocket upgrade: a present
Origin header must match `cfg.BaseURL` on scheme + host exactly, not a
substring. A missing Origin (non-browser client) is allowed. This closes
cross-site WebSocket hijacking, where a hostile page would otherwise ride
the browser's SameSite=Lax session cookie to open a socket. Rejections log
`ws.origin_rejected`.

Source: `pkg/httpsec.OriginAllowed`, `pkg/ws/ws.go`, `pkg/web/admin_mqtt.go`.

### A socket lives at most ws.MaxLifetime

The session is checked only at the upgrade. Both sockets close after
`ws.MaxLifetime` (10 minutes) with close code 4000 (`ws.ReauthCloseCode`),
and both pages reconnect on it, which runs the auth middleware again. A
revoked session or a demoted super-admin loses the stream or the shell
within that time.

How verified: `pkg/ws/ws_test.go`, `pkg/web/admin_mqtt_lifetime_integration_test.go`.

---

## PKI and mTLS

### Device certs are ECDSA P-256 with PKCS#8 private key envelope

P-256 keeps the cert + key small (cellular modem internal FS has a
~4 kB ceiling per file). PKCS#8 (not the older OpenSSL "EC PRIVATE
KEY" envelope) is required by SIM7080G firmware 1951B17; the
provisioner uses PKCS#8.

Source: `pkg/pki/ca.go`, `pkg/pki/sign.go`.

### A device cert warns 30 days before it expires

Device certs live `pki.DeviceCertValidity` (365 days) and nothing renews
them; the device is offline on the mTLS listener once `not_after` passes.
The alert sweep raises one `warn` alert with code `cert_expiring` per
active certificate that expires within `CertExpiryWarning` (30 days),
keyed by serial in `raw`, so a cert is warned once. A cert already past
`not_after` still gets the alert, worded as expired, so a dead device is never silent. The alert clears once
that serial is no longer the device's active, unrevoked cert (re-pair or
revoke). The fix for the device is a re-pair.

How verified: `pkg/service/cert_expiry_sweep_integration_test.go`.

Source: `pkg/service/cert_expiry_sweep.go`, `pkg/pki/ca.go`.

### Internal CA private key: KMS migration **(WIP)**

Mitigated by passphrase encryption (see the CA-private-key-encrypted-on-disk
invariant above). Long-term: move signing to a KMS (AWS KMS / GCP KMS /
Vault transit engine) so the server never sees the private key.

Source: `pkg/pki/ca.go::generate`.

### Device-CN topic-tenant cross-check on auto-create **(WIP)**

Today device auto-creation from MQTT trusts the topic-claimed tenant.
The FK constraint on `tenant_id` rejects non-existent tenants, but a
misconfigured ACL plus an existing tenant can land a `devices` row
in the wrong tenant. Target state: for paired devices, parse the
cert CN and reject the upsert if the topic tenant disagrees.

Source: `pkg/mqtt/mqtt.go::parseTopic`,
`pkg/service/device.go::upsertCore`.

---

## MQTT broker integration

### Devices authenticate via mTLS dynsec with cert-only clients (no password)

Dynsec client per paired device with empty password; auth resolves
to the cert CN on the mTLS broker listener (port 8884).
Non-paired / non-mTLS clients use password auth on the legacy
listener (port 8883). The split keeps mTLS optional during the
multi-tenant rollout but mandatory for any device that has a cert.

Source: `pkg/web/admin_pair.go`, `pkg/mqtt/dynsec.go`.

### Revoke and delete refuse to strand a paired device

A paired device walked off mTLS needs the shared fallback credential to get
back onto the broker. Single delete, bulk delete and admin revoke all probe
that credential first (`recoveryPath`) and, for a paired device with
an unusable path, refuses before the certificate is touched. The operator
can override with `accept_serial_recovery=true`, which is logged; the
override exists because the fallback credential was removed from the broker
and portal re-enrollment is not shipped yet, so serial recovery is the only
route back. Everything after the committed revoke runs on
`context.WithoutCancel` with a timeout per step, the audit row included,
and an enrollment reset that fails is surfaced on the redirect (a `sealed`
count on bulk), never reported as success. `serial_recovery_accepted` is
recorded only when the override did the work: a paired device, no usable
path, box ticked. An unpaired device passes the gate with nothing recorded.

Tenant delete runs the bulk cascade over the tenant's devices with the same
gate and the same `accept_serial_recovery` override on its form. A refused
or failed device keeps the tenant. On every delete path, single, bulk and
tenant, a broker client whose teardown failed is flagged
`broker_teardown_failed: true` on that device's `device.delete` audit row
and named on the page, because the per-device alert cascades away with its
device. The `tenant.delete` row does not repeat it.

Bulk delete and tenant delete run the per-device cascade as a job, because
about 2 s per paired online device plus up to 30 s per broker timeout
outlasts the edge proxy's 50 s. The POST does the checks that need the
request (selection, cross-tenant gate, protected tenant, device list), reads
the override, and answers 302 to `/admin/jobs/{id}`. That page refreshes
every 2 s with done of total, and redirects to the outcome page once the job
ends. The outcome travels as registered flash codes, never as text. Jobs
live in the in-memory `requestStore` the device CLI uses, so a restart loses
the job page: every device it finished stays finished, the tenant row goes
last, and the delete can be submitted again.

Shutdown drains jobs (`DrainJobs`, `gracefulShutdown`). New jobs get 503 and
running ones see their context cancelled, so the next device is never
started. The device in progress finishes, every step on
`context.WithoutCancel`, unless the drain has less than `stopMargin` (3 s)
left when it reaches `DeleteByID`. Then it stops there and keeps its row,
revoked, for a retry. The wait is `jobBudget` (18 s), under the 20 s
`stop_grace_period`, then MQTT and the pools close. A job that ends within
`jobBudget` after stopping any device writes one audit row with
`stopped_for_shutdown: true`, `not_started` and `revoked_not_deleted` (a
`tenant.delete` row with `kept: true`, or a `device.delete` row on target
`devices` for bulk). Past `jobBudget` the job's remaining audit rows, that
one included, may be lost, and the shutdown log `admin job cut off` is the
record. A device cut off after `DeleteByID` has no tombstone and keeps its
claim until the boot sweep clears it.

How enforced: `destructiveAllowed` (`pkg/web/admin_devices_bulk.go`) is the
one gate, unit-tested for all eight input shapes; `recoveryGate` is the
only way a single-device handler reaches it. Tenant delete, the broker
flag and the bulk delete job are integration-tested (`TestAdminTenantDelete_*`,
`TestAdminDeviceDelete_BrokerTeardownFailureOutlivesTheDevice`,
`TestAdminBulkDelete_RunsAsAJob`), the job page is unit-tested
(`TestAdminJob_*`). The drain is unit-tested (`TestDrainJobs_*`,
`TestGracefulShutdown_*`) and integration-tested against both stop points
(`TestAdminDeleteJobs_*`). The tenant-scoped reset is integration-tested on
every admin path (`TestAdminDelete_*`, `TestEnrollmentReset_*`,
`TestEnrollmentSweepOrphanClaims`). Owner revoke is the one
exception, below: it never walks the device to the fallback credential.

### Owner revoke re-enrolls, it does not fall back

`POST /devices/{id}/revoke` looks the device up through `deviceInScope`
with `CertRevoke`, so only a super-admin reaches outside the effective
tenant. Only the device's `owner_user_id` or a super-admin passes; anyone
else, including a user of another tenant, gets a 404. The outcomes:

| Device state                                   | Result                                    |
| ---------------------------------------------- | ----------------------------------------- |
| No owner (admin-paired)                        | `revoke_no_owner`, for everyone who passes; admin path only |
| Another tenant has claimed the device id       | `revoke_not_held`; that tenant's rows survive |
| Unpaired and no claim anywhere                 | `revoke_already`; nothing is sent again   |
| Paired here, or claimed only by this tenant    | revoked                                   |

Order on success: `EnrollmentService.ResetForTenant`, then
`Certificates.Revoke`, the audit row, `cert.clear` (QoS 0, then 800 ms so
the broker client outlives delivery), and the dynsec teardown last.
`ResetForTenant` locks the device id's rows before its claim check, so a
claim by another tenant that lands after the page check is refused with
nothing changed; running it first also means the rows are gone before the
device announces again. `cert.clear` is the only command: the firmware drops
the session on it, so nothing sent after it arrives. No port flip and no
fallback credential, so the recovery-path gate does not apply: a claimed
device got its cert over HTTPS enrollment and gets the next one the same
way. A failed reset shows `revoke_failed` with nothing changed. A cert
revoke that fails after the reset shows `revoke_cert_failed`: the rows are
gone and the cert is live, and the audit row records `cert_revoked: false`
so the state is visible. A publish that did not go out shows
`revoke_unsent`. A `cert.clear` that removed a cert reboots the unit
about 3 seconds later, and that boot starts enrollment again. Success means
the device was told. A unit still on a build from before that reboot waits
for its next restart.

How enforced: `revokeGate`, `decideRevoke`, `revokeConfirmed` (`pkg/web/device_revoke.go`)
and `DeviceHolder` (`pkg/service/enrollment_policy.go`), unit-tested;
`ResetForTenant` and the handler, integration-tested
(`TestEnrollmentResetForTenant_RefusesAnotherTenantsClaim`,
`TestOwnerRevoke_*`).

### Retained MQTT deliveries are never acted on as live

A retained flag on delivery means the broker replayed a device's last
publish to a fresh subscription, which is every app restart. Nothing treats
that as the device talking: `handleInfo` skips drift work on a retained
`info` (the pull would race a device that has not reconnected yet),
`handleAlert` neither stores nor notifies a retained alert, `handleSensor`
drops a retained reading before it can bump `last_seen_at`, clear an open
absence alert or store telemetry, and the CLI response tap drops a retained
reply. A `status` or `info` replay still upserts the row, without the
`last_seen_at` bump. The `info/retained_topics` manifest is cached from a
replay and from a live delivery alike, because a running app sees every
manifest update live, and an empty one (the broker forwarding a retained
delete) drops the cache entry. Separately, `InsertAlert` refuses the
same JSON payload from the same device inside a 10 minute window, so QoS 1
redelivery after a reconnect cannot notify twice; the insert retry treats
that refusal as "already stored" and leaves delivery to the redispatch
sweeper.

How enforced: the retained flag is checked in each handler in
`pkg/mqtt/mqtt_ingest.go` and in `tapCLIResponses`. The dedup window is an
integration test on `AlertService`, and the sensor drop is
`TestHandleSensor_RetainedReplayIsNotALiveReading`.

### CLI responses are read from `cli_response` only

Firmware publishes CLI responses to `<prefix>/cli_response`, outside the
`<prefix>/cli/#` wildcard a device subscribes to, so a device never receives
its own responses. `tapCLIResponses` subscribes to that one topic. The
pre-split `<prefix>/cli/response` is no longer read: every fielded device runs
firmware at or past the split (26.08.0), and a device on older firmware would
go mute on CLI against this platform.

How enforced: every CLI topic is built by `pkg/mqtt/topics.go`; no topic
literal is assembled at a call site, in `pkg/mqtt` or in the web handlers.

Source: `pkg/mqtt/mqtt_cli.go::tapCLIResponses`, `pkg/mqtt/topics.go`. Pairs
with the thesada-fw invariant "CLI responses publish outside the command
wildcard".

### CLI requests serialize per device + correlate by req_id

`CLIRequest` / `CLIRequestRaw` hold `cliLockFor(topicPrefix)` for the
full publish-then-await cycle. Two concurrent callers targeting the
same device queue on that mutex; the second goroutine does not
register a tap or publish until the first has consumed its response
or timed out. Without the mutex both taps fire on every response
message and the loser captures the winner's reply.

Outgoing payloads (text path only) are wrapped as `{"req_id":<uuid>,
"args":<original>}`. Firmware v1.4.5+ echoes req_id back on every
response; `cliMatchesRequest` filters by req_id when both sides have
one.

Firmware unwraps `args` before its binary handlers too, so `cert.set`
and `secret.set` go through `CLIRequestFields`, which envelopes the
`<key>\n<value>` payload and correlates on req_id. A payload JSON cannot
carry byte for byte (invalid UTF-8, NUL) falls back to the raw path.
`fs.write` and `fs.append` chunks stay on `CLIRequestRaw` without a
wrap: JSON escaping would grow a 3900-byte chunk past the device input
buffer, and a chunk cut inside a UTF-8 rune would be rewritten. The
mutex still serializes.

A request whose deadline ran out while it waited for the mutex returns
the deadline error without publishing, so a caller that already gave up
never has its command land later (`cli_lock_wait_integration_test.go`).

Where there is no req_id to correlate on - the raw path, and firmware
predating v1.4.5, below the supported floor - `cliMatchesRequest` falls back to the command name,
which every response carries. The mutex alone is not sufficient: it
guarantees one outstanding request, not that a late reply to the
PREVIOUS command has stopped arriving. A straggler landing inside the
next request's window is otherwise consumed as that request's reply,
reading a device error as the previous command's success. A response
naming no command at all is accepted rather than dropped, so an
unknown-but-valid reply degrades instead of hanging.

A command match cannot tell two `fs.cat` chunk replies apart, so every
chunked read checks the `offset` the firmware echoes on each chunk:
`ReadFileChunked` (drift pull, Load from device) and the rename readback
fail the read on a reply without `offset` or for another offset, before
its data is kept (`TestNextChunk_RefusesAReplyForAnotherOffset`). A reply
with `done: false` and no `length` fails the read too, it would pass a
truncated prefix as the whole file (`TestNextChunk_StopsWithoutProgress`).

Multi-page consumption: firmware v1.4.6+ splits oversized command
output across multiple response messages, each carrying a
0-indexed `page` and a `more` flag (final page `more:false`). Both
`CLIRequest` and `CLIRequestRaw` await the assembled result via
`awaitPagedCLIResponse`, which keys page output by index (arrival
order does not matter) and returns once the final page plus every
lower-indexed page has arrived. The returned `CLIResponse` has
`Page`/`More` cleared and `Output` holding the concatenation. The tap
channel is buffered (cap 64) so the non-blocking sink send never
drops an intermediate page. Pre-1.4.6 firmware omits `page`/`more`
entirely - its single message is treated as the final page and
returns immediately, so the path is mixed-fleet safe.

How enforced: every CLI caller goes through `Client.CLIRequest` or
`Client.CLIRequestRaw`. Reviewers reject direct `c.PublishRaw` calls
to `*/cli/<cmd>` topics from outside `pkg/mqtt`; the topic is built by
`mqtt.CLICommandTopic`.

Source: `pkg/mqtt/mqtt.go::CLIRequest`, `CLIRequestRaw`,
`awaitPagedCLIResponse`, `cliLockFor`, `pkg/mqtt/mqtt_snapshot.go::nextChunk`. Pairs with the thesada-fw
`docs/invariants.md` invariant "cli_response paginates oversized
command output".

### `/info` drift detection runs on every live delivery

The firmware publishes `<prefix>/info` on every MQTT reconnect. On a live
(non-retained) delivery from a paired device, `handleInfo` compares the
device-reported `config_hash` / `scripts_main_hash` / `scripts_rules_hash`
against the latest stored snapshots. A mismatch hands the paths to
`pullDrift`, which pulls them one at a time over the per-device-serialized
CLI path and then discovers untracked scripts. Each pull writes a
`source="drift"` row into device_files. Every round trip (`config.dump`,
each `fs.cat` chunk, the `fs.ls` discovery) waits up to
`THESADA_CLI_REQUEST_TIMEOUT`, the budget operator commands get, so a
cellular device is not cut off at a fixed 10 or 15 s.

The retained replay at app restart does not trigger drift work (see
"Retained MQTT deliveries are never acted on as live"). A delta that built
up while the app was down is picked up at the device's next reconnect.

Source: `pkg/mqtt/mqtt_ingest.go::handleInfo`, `pullDrift`,
`pkg/mqtt/mqtt_snapshot.go::pullAndSnapshot`.

---

## Alert delivery

### Every alert row reaches a terminal delivery state; pending rows are always swept

`device_alerts.delivery_status` is the lifecycle: `pending` ->
`delivered` / `none` (no matching subscription) / `dead` (attempt
budget spent, `THESADA_ALERT_MAX_ATTEMPTS`, default 5). A failed send,
or a panic while rendering or sending, leaves the row `pending` with a
backed-off `next_attempt_at` and the channels that already sent kept. The
redispatch sweeper (`Notifier.StartRedispatcher`, one pass at startup
+ one per `THESADA_ALERT_REDISPATCH_INTERVAL`) re-runs `Dispatch` for
every pending-and-due row. A process death between insert and dispatch
is therefore recovered at next boot, and all-channels-fail is surfaced
as an `alert.delivery.state_change` to `dead` at error level - never
silently dropped.

The sweep scan is the one sanctioned cross-tenant read in the alert
path: it runs on `pools.Admin` via `db.WithAdminAudit` and reads only
`(tenant_id, alert id)` pairs; each re-dispatch then runs tenant-scoped
via `db.WithTenant` like the inline path. Per-channel `delivered_*`
flags normally keep a retry from re-sending a channel that already
succeeded - the guarantee holds once the outcome write lands; if that
write fails the row stays pending and the next sweep can re-send a
channel that succeeded this run (accepted: duplicate beats lost, see
`recordOutcome`). Channel success is per-alert, not per-recipient
(partial recipient failure within a channel is not retried). The
in-process `inflight` claim assumes a single app instance - running
more than one needs `FOR UPDATE SKIP LOCKED` claims first.

How verified: `pkg/alerts/alerts_integration_test.go` (retry
scheduling, dead-letter budget, cross-tenant sweep, startup-shaped
redispatch, no-double-send on partial channel failure, a panicking row
backing off to `dead`).

Source: `pkg/alerts/alerts.go::Dispatch`, `pkg/alerts/redispatch.go`,
migration `0025_alert_delivery_retry.sql`.

### An alert goes to enabled channel rows, once per channel

A user's destinations are rows in `notification_channels` (`email`,
`telegram`, `webhook`, each with one target and an `enabled` flag). A
subscription keeps its device and severity filter and points at one channel
through `channel_id`. Dispatch joins the matching subscriptions to their
enabled channels and sends once per channel: a device rule and an
all-devices rule on the same channel send one message, and a switched-off
channel sends nothing. A target is checked per kind on every write (a bare
address, a numeric chat id, the webhook URL rules below). The rows are RLS
policed through `users`, and every settings route checks the channel belongs
to the caller. Migration 0043 built the rows from `users.email`,
`users.telegram_chat_id` and `alert_subscriptions.destination` as the
BYPASSRLS role. Those columns stay for one release: the app no longer writes
`telegram_chat_id`, and it mirrors the channel kind and webhook URL into
`alert_subscriptions.channel` / `destination` so a rollback to 26.11.4 still
delivers. The next release drops them.

The account's own email channel has `follows_account` (one per user, email
only, 0044 set it on the channel 0043 built from `users.email`). Its target
is `users.email` at send time and in every listing, never the stored copy,
so an email change moves alerts with it. The settings page edits only its
label and enabled flag, and it can be removed. A kind-only email
subscription (the API) binds to it. Email channels a user adds stay plain
targets.

An email channel sends only once its address is confirmed (0047). A new or
changed address that is not the account's own (compared case-insensitively)
starts unconfirmed and gets a confirm link: 32 random bytes, only the sha256
stored on the row, valid 24 h, single use. A changed address clears the old
link. An edit locks the channel row before it reads the old address, so two
concurrent edits cannot keep a confirmation for an address that never had a link. `GET /alerts/channels/confirm` only shows a button (a mail scanner
confirms nothing), the POST confirms. An unknown, used or expired link gets
one plain "not valid" page. The confirm routes are public and key on the hash
alone through the BYPASSRLS pool. Confirm mails (add, change, resend) are
capped at 3 per user per hour. Over the cap the channel is saved, no mail
goes out, and a live link stays valid. Dispatch, `AlertCoverage` and
`CountSubscribersAny` skip unconfirmed email channels. `follows_account`,
telegram and webhook rows are never gated. 0047 marked every email channel
that existed before it confirmed.

How verified: `pkg/service/notification_channels_migration_integration_test.go`
(0043 on the production role, old-shape fixtures), `pkg/alerts/channels_migrated_integration_test.go`
(a migrated user gets email, telegram and webhook once each, a disabled
channel sends nothing), `pkg/service/alert_channel_integration_test.go`
(target checks, tenant isolation, the account channel after an email change),
`pkg/service/alert_channel_confirm_integration_test.go` (with a forced concurrent edit),
`pkg/alerts/channel_confirm_integration_test.go` (unconfirmed gets no mail,
with a negative control on the dispatch filter),
`pkg/web/channel_confirm_integration_test.go` (GET changes nothing, cap),
`pkg/web/cross_tenant_integration_test.go`.

Source: `pkg/service/alert_channel.go`, `pkg/alerts/alerts.go::loadRecipients`,
`pkg/web/web_settings.go`, migrations `0043_notification_channels.sql`,
`0044_channel_follows_account.sql`, `0047_channel_email_confirm.sql`.

### A webhook is posted once per alert, and not into the internal network

A subscription with channel `webhook` is a third delivery channel. Dispatch
POSTs a JSON body (`alert_id`, `device_id`, `severity`, `code`, `message`,
`received_at`) to its channel's target. `code` is always
present; an alert with no code sends an empty string. `delivered_webhook`
is the same retry flag as email and telegram, and the device-alerts JSON
includes it beside those two flags. A later attempt does not
post a URL that already returned success. If one of several webhook destinations fails, that subscription is
not recorded. The retry POSTs only the subscriptions that have no
delivery row. The channel flag is set when every one has succeeded. A
delivery row is accepted only when that subscription's user is in the
device's tenant, and the subscription names that device or every device.
The URL must be http or https
with a host. Loopback, link-local, and redirects are refused. Private
(RFC 1918, fc00::/7) and CGNAT (100.64.0.0/10, the NetBird overlay)
addresses are refused too, because from the server a tenant's webhook would
otherwise reach the internal network. An operator opens specific ranges with
`THESADA_WEBHOOK_ALLOW_CIDRS` (comma-separated IPs or CIDRs, e.g. a home
Home Assistant); loopback and link-local stay refused even when listed. The
check runs on the stored URL and again on every dial, against the resolved
address.
A refused destination is not copied into the error, so a token in the
URL does not land in the log.

How verified: `pkg/alerts/webhook_test.go`, `pkg/service/notify_channel_test.go`.

Source: `pkg/alerts/webhook.go`, migration `0035_alert_delivered_webhook.sql`, migration `0038_alert_webhook_deliveries.sql`.

### A paired device that goes quiet raises one absence alert per stretch

The offline badge and the absence sweep share a 15 minute window
(`service.AbsenceWindow`). Each pass inserts one `warn` alert with code
`absence` for a paired device whose `last_seen_at` is older than that
window, and only when no absence alert has been recorded since that
`last_seen_at`. A device that has never reported is not an absence.
The redispatch sweeper delivers the new row. The open-absence lookup
index is built concurrently so alert writes are not blocked. A failed
build leaves the index invalid, and the next migrate drops it and
tries again before recording success. A later live sighting sets
`cleared_at` on that absence row, and the alerts page shows cleared.

How verified: `pkg/service/alert_rules_test.go`.

Source: `pkg/service/absence_sweep.go`, `pkg/service/alert_rules.go`,
`pkg/service/device.go`, migration `0036_absence_cleared.sql`.

### A trend rule costs one query per reading and raises one alert per episode

A trend rule (`alert_rules`, kind `trend`, tenant RLS) fires when a numeric
reading moved at least `delta` from the baseline, the newest sample of that
device and metric between two windows and one window old. No baseline in that
span means no decision, so a long silence never reads as a jump. Every numeric
reading runs `EvaluateTrends` once: one statement returns the matching rules
with their baseline and open alert, both index lookups
(`device_telemetry_device_metric_time_idx`, `device_alerts_open_trend_idx`).
It writes only when the state changes: no open alert raises one, an open one
older than the window raises again, a reading that no longer fires clears it.
The alert code is `trend.<metric>`, the payload names the rule and carries the
evaluation time, so a new episode is not taken for a redelivery. A rule's
metric is the name ingest stores, so it may hold slash-separated segments
(`current/house_pump`, the whole sensor sub-path). It is only ever bound as a
query parameter and escaped as page text, never put into generated Lua. A rule's
device must belong to the tenant, checked in the service because the foreign
key alone would accept another tenant's device. Switching a rule off or
deleting it clears its open alerts.

How verified: `pkg/service/trend_rules_test.go`,
`pkg/service/trend_rules_integration_test.go` (fire once, suppression inside
the window, clear, re-fire after it, slow fall, other tenant, one statement
per reading, each with a negative control), `pkg/db/rls_integration_test.go`.

Source: `pkg/service/trend_rules.go`, `pkg/mqtt/mqtt_ingest.go`
(`evaluateTrends`), migrations `0045_trend_rules.sql`,
`0046_trend_open_index.sql`.

### A tenant with a paired device has a subscriber, or is told it has none

Every path that sets `paired_at` (`Issue`, `IssueWithIdentity`, `Activate`)
checks, in the same transaction, whether the tenant has any alert
subscription. With none, it subscribes one user on all devices at `warn`
through their account email channel: the device owner (the claiming user),
else the oldest tenant admin, else the oldest user. Pairings in one tenant
serialize on a transaction advisory lock, so parallel pairings add one row,
and a re-pair finds the row and adds nothing. The step runs in a savepoint:
a failure logs `alert.subscription.default_failed` and the pairing still
lands. A tenant without users pairs and logs `alert.subscription.default_skipped`.

While the tenant has a paired device and no user with a subscription on an
enabled channel, `/devices` and `/alerts` show "Nobody gets alerts for this
tenant" with a link to the alert settings. The admin tenants list shows that
subscriber count per tenant.

How verified: `pkg/service/alert_default_integration_test.go` (each pairing
path, re-pair, an existing subscription left alone, a tenant without users,
six parallel pairings adding one row), `pkg/web/alert_coverage_integration_test.go`
(banner on both pages, gone after pairing, admin subscriber count).

Source: `pkg/service/alert_default.go`, `pkg/service/certificate.go`,
`pkg/web/web_device.go::alertsUnheard`, `pkg/web/templates/layout.html`.

### A failed alert insert retries bounded, then dead-letters to the log

`handleAlert` retries a failed `device_alerts` insert in the background
(3 attempts, 5s/15s/45s, capped at 64 concurrent retry goroutines) and
on exhaustion emits `alert.ingest.dead_letter` at error level with the
full payload, so the alert is reconstructable from logs. Until the
insert lands the alert exists only in process memory - MQTT QoS 1
redelivery on reconnect is the transport-level backstop.

Source: `pkg/mqtt/mqtt_ingest.go::retryAlertInsert`.

---

## Rate limiting

### Magic-link and reset endpoints are rate-limited per IP + per email

Window-based limiter (`pkg/ratelimit`). A request is dropped silently
when the client IP is over its cap or when the address itself is over
its wider cap. The IP cap is checked first so a client already over
quota does not create an address key. A rejected address does not
spend that client's own cap, and the two caps are reserved together so
a lost client slot does not spend the address. One client cannot spend
the address cap alone. The handler still returns the same sent result,
leaking neither which addresses exist nor whether a request was
throttled. There is no 429. Map sweep removes empty entries on the
window cadence so the map does not grow unbounded over the lifetime of
the systemd unit.

Source: `pkg/ratelimit/ratelimit.go`, `pkg/notify/notify.go`
(`RequestLoginLink`, `RequestResetLink`). The dashboard login and
forgot-password handlers and `POST /api/v1/auth/magic-link` all call
those two.

### Password login is rate-limited per email + per IP and answers 429

The same window limiter brakes online password guessing, but here at the
service layer (`AuthService.allowLogin`, checked inside
`VerifyPasswordAnyTenant`) so the web form and `/api/v1/auth/login` are
covered by one gate rather than each handler. Per-email and per-IP buckets
(`loginMaxPerEmail` / `loginMaxPerIP` over `loginWindow`); over the cap
returns `ErrLoginRateLimited`, which the handlers surface as **429** (web
re-renders "too many attempts", API returns a 429 JSON body).

Unlike magic-link, login answers 429 rather than silent-dropping: login
already has a visible failure mode (wrong password), and the limiter keys
on (email, IP) independently of whether the account exists, so a throttle
response leaks no user enumeration - it only confirms the caller has been
hammering, which the caller already knows.

The per-IP key is the real client IP via `httpsec.ClientIP`, which honours
`X-Forwarded-For` only from a peer in `THESADA_TRUSTED_PROXIES` (walked
right-to-left, so a client-spoofed prefix is ignored). Without that env the
key is `RemoteAddr`; behind the TLS proxy every request shares the proxy IP,
so the proxy MUST be in the trusted set for the per-IP cap to be per-client
rather than a global bucket.

How verified: `pkg/service/auth_throttle_test.go` (per-email cap, per-IP
cap, empty-IP isolation, case-insensitive email key) and
`pkg/service/auth_users_integration_test.go::VerifyPasswordAnyTenant_rate_limited_per_email`
(the gate trips end-to-end and refuses even the correct password while full).

Source: `pkg/service/auth.go::allowLogin`,
`pkg/service/auth_users.go::VerifyPasswordAnyTenant`,
`pkg/web/web_auth.go::handleLoginSubmit`,
`pkg/api/v1/auth.go::handleAuthLogin`.

---

## Audit trail

### Every cross-tenant admin read writes an audit log entry **(WIP)**

Target state once `db.WithAdminAudit` wires the audit table.
Currently the helper exists and writes a log line; the audit table
schema is scaffolded but not consumed by any handler yet. Cross-
tenant admin operations today rely on the `*Any` naming + the
`RequireSuperAdmin` middleware as the only enforcement layer.

Source: `pkg/db/tenant.go::WithAdminAudit`.

### Security state transitions emit `<subsystem>.state_change`

Auditable state edges log a structured transition (`from`/`to` + ids) so the
trail is greppable. Wired so far:

- `auth.session.state_change` - login (anonymous -> authenticated, with method)
  and logout (authenticated -> anonymous). Source: `pkg/web/web.go::startSession`,
  `handleLogout`.
- `oauth.identity.state_change` - an external identity bound to a local user
  (unlinked -> linked), `trigger` is `settings_link` or `email_match`. Sign-in
  itself rides `auth.session.state_change` (method `oidc`).
  Source: `pkg/web/oauth.go::handleOIDCCallback`.
- `device.pair.state_change` - a device's pairing cert issued (unpaired ->
  paired) or revoked (paired -> revoked) via pair issue, admin revoke, or single
  / bulk device delete; `reason` names the trigger. Revoke/delete only log when
  the device was actually paired. Source: `pkg/web/admin_pair.go::logPairStateChange`.
- `alert.delivery.state_change` - an alert notification delivered (pending ->
  delivered) once at least one channel (email/telegram) succeeds and the
  device_alerts row is marked. Source: `pkg/alerts/alerts.go::Dispatch`.

Device OTA is intentionally absent: the app fire-and-forgets a `cli/ota.check`
command and the device owns the update lifecycle, so there is no app-side
`state_change` to emit for it.

---

## Error handling

### `recover()` only on goroutines fed by external input

Standard handlers return appropriate HTTP codes for every error path; nil
derefs are guarded at boundaries (request parse, DB scan, external service
call), so most goroutines need no recover. The exception is a goroutine
reachable by external input: `pkg/mqtt` dispatches every inbound broker
message on its own paho goroutine, so `onMessage` recovers at entry
(`mqtt.callback_panic`) - one malformed message must not crash the process.
net/http recovers a handler's own goroutine, never one the handler starts.

Goroutines that `onMessage`, a handler or a sweep starts with device or
request input run under `safego.Go`. A sweep loop over rows that carry
device-supplied text (`alerts.redispatch`: alert message, code and
recipients) wraps each row in `safego.Run`. A panic logs one
`goroutine.panic` line at error with `site`, the panic value and the stack.
It never passes silently, and it never takes the process down.

| Site | Input | On panic |
|------|-------|----------|
| `mqtt.alert_insert_retry` | device alert | retry slot freed, the line carries the dead-letter fields |
| `mqtt.alert_dispatch` | device alert | counts as one delivery attempt, the redispatch sweep retries after backoff |
| `mqtt.drift_pull` | device CLI output | remaining paths of that pull skipped |
| `alerts.redispatch` | device alert row | counts as one delivery attempt, `dead` at the budget, the pass goes on |
| `web.cli_cmd`, `web.cli_write` | admin request, device CLI output | a still-pending request marked error, a done one kept |
| `web.admin_job` | admin bulk or tenant delete | job finishes at its failure flash |
| `web.waitlist_notify` | public signup form | admin mail not sent |
| `web.mqtt_shell_writer` | broker traffic to the shell | shell socket closed |
| `ws.write_pump`, `ws.read_pump` | browser socket | socket closed and unregistered |

Sweeps whose rows hold only app-owned fields (absence, cert expiry), pruners
and the HTTP listener stay unguarded, so a panic there stops the binary.

New code that adds a goroutine MUST start it with `safego.Go` if device or
user input can trigger it. Reviewers grep for new `go func()` and `go `
statements at PR time.

How enforced: `pkg/safego` tests, plus one test per site that injects a panic
(`TestPullDrift_*`, `TestFinishAlert_*`, `TestRetryAlertInsert_*`,
`TestGoCLI_*`, `TestStartJob_*`, `TestNotifyAdminWaitlist_*`,
`TestSweep_PanickingRowDoesNotStopThePass`). The shell writer and the ws
pumps have no injection seam and rely on review.

---

## What this list is not

- Not a feature spec.
- Not a coverage map.
- Not a roadmap.

It is the list of properties this app must keep true to remain
defensible. Reviewers consult it on every PR that touches the named
files. Update it before merging anything that violates an entry, or
the entry is wrong.

Related: [`../CODE-GUIDELINES.md`](../CODE-GUIDELINES.md),
[`security.md`](security.md) (Go security scanner gating).
