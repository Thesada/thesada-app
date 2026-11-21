# Operational runbook (app)

Recovery procedures for a stranger on call. Numbered steps, decision trees, real commands. Update whenever the answer changes. Capabilities and their exact routes are in [`operator-role.md`](operator-role.md); failure signals are in [`failure-modes/`](failure-modes/).

Convention: `admin UI` = a `/admin/*` route (super-admin session). `CLI` = `thesada-app <cmd>` on the host shell.

---

## MQTT broker down

Symptom: devices stop reporting; alerts stop. `/readyz` reports `degraded` with `mqtt:false`; `/healthz` stays ok by design (liveness only). Logs: `mqtt.connection.state_change`.

1. Confirm it is the broker, not the app: check the app logs for `mqtt subscribed` on the last restart and for reconnect churn. Check the broker host directly (`systemctl status mosquitto`, its own logs).
2. If the broker process is down: restart it on the broker host. The app auto-reconnects (`SetAutoReconnect`, 5s) and re-subscribes on `OnConnect` - no app restart needed.
3. If the broker is up but the app is not connected: restart the app; watch for `mqtt subscribed`.
4. Backfill: device state is republished by devices on their own cadence; retained topics restore the last values. No manual replay exists.

## MQTT broker compromised

Assume broker credentials and/or the dynsec store are untrusted.

1. **Contain:** stop the broker or block its port at the firewall.
2. **Rotate the app's broker login:** it is a static env value (`cfg.MQTTPassword`) - change it in the broker + the app env, restart the app.
3. **Per-device identity:** device clients are cert-auth (dynsec, empty-password). There is **no** "rotate a tenant's MQTT credential" tool (#gap, see operator-role.md). To re-key a device you must **revoke + re-pair** it: `/admin/devices/{id}/pair/revoke` then `/admin/devices/{id}/pair/issue`.
4. **If the CA is suspected compromised:** this is the worst case. There is no one-click CA rotation. It means: stand up a new CA, re-issue every device cert, and re-pair the fleet. Treat as an incident, not a runbook step - **procedure to be built** (tracked alongside the CA-rotation gap).
5. Verify: revoked dynsec clients can no longer connect; confirm the broker rejects the old app credential.

> Decision: single device suspect -> revoke+re-pair that device. Broker creds suspect -> rotate app login + revoke affected device clients. CA suspect -> incident, full re-pair.

## OTA push failed mid-fleet

1. Check per-device OTA status on the `status/ota` topic (`{"state":"refused|failed|..."}`) or the device list.
2. Common `reason` values and meaning: `no-transport` (device offline - retries next interval), `manifest-fetch-failed` (origin/manifest problem - fix the artifact), `heap-low` (device skipped on low heap - it retries on next clean boot), `no-ca` (device has no CA and `ota.allow_insecure` off).
3. Re-trigger: `/admin/devices/bulk` action=ota (`cli/ota.check --force`) to the affected devices.
4. A failed download does **not** flash - devices stay on the current image (SHA256 + abort on mismatch). No rollback needed for a failed download.
5. If a device flashed and then rebooted onto a bad image: see the firmware runbook (bricked device) - and note the known gap: the app may not mark the new image valid; verify rollback behaviour.

## Cert expired on a device fleet

1. Identify: devices fail mTLS and fall back to password auth (fw logs `mTLS: ... password fallback`), or drop off if password auth is not provisioned.
2. Re-issue per device: `/admin/devices/{id}/pair/issue` (signs a fresh cert, pushes it, marks paired). Bulk re-issue is not a single action today - script over the affected device IDs.
3. Verify the device reconnects with the new cert (broker log / device `info`).

## Tenant data leak suspected

1. **Scope it:** cross-tenant reads go through the audited BYPASSRLS pool - search logs for `rls.admin_audit` to see every cross-tenant access and by whom.
2. Confirm the leak path: was it a query missing its tenant scope (missing-tenant-scope class), an over-broad admin action, or a leaked session/token?
3. **Contain:** if a session/token is implicated, the operator can force logout by deleting the session row; rotate any exposed credential.
4. Preserve the audit trail before remediating. File the specific missing-scope query as a bug.
5. Note: super-admin can read **and write** across tenants (see operator-role.md) - rule that path in or out explicitly.

## DB role lockout

1. Symptom: the app cannot connect or a background job (continuous aggregate refresh) fails on a role error.
2. Check which pool is affected - App / Admin(BYPASSRLS) / MQTT are separate roles (`cmd/thesada-app/main.go:44`).
3. Known gotcha: a continuous-aggregate owner role needs `rolcanlogin`; if a role was created `NOLOGIN`, refreshes fail. Grant login on that role. *(Exact SQL: verify against the deploy before running.)*
4. If migrations are stuck: `thesada-app migrate` on the host. See [Migrations](#migrations) for the role grant they need.
5. Restore path (if the DB itself is lost): TimescaleDB restores must be **version-matched** to the dump.

## Self-host upgrade

`deploy/startup.sh` creates the timescaledb extension when it is missing, then runs `ALTER EXTENSION timescaledb UPDATE` before the migrations.

1. Docker Compose 2.17 or newer is required (`up --wait`). The script stops on an older one.
2. Rerunning it on a live stack recreates the database container when the image changed. The app loses its database for that restart, and the ALTER takes catalog locks against live sessions. Run it in a quiet window.
3. Rolling the image back to an older timescaledb than the volume holds fails the ALTER, and the script stops before the migrations. The database container already runs the older image by then, so the stack is not as it was. Put the newer timescaledb image back in the compose file and rerun the script, or restore the database from a backup made before the upgrade.
4. Update devices to firmware 1.4.5 or later before the app rollout. The app refuses file saves and rule pushes to older or unknown firmware with a 409 naming 1.4.5, and drift pulls skip it with `drift pull skipped, firmware below the supported floor` in the log.
5. The release PR runs `make release-pin RELEASE=<version>`, so the compose file in a release tag runs that release. `go test ./deploy/` fails when the pin is older than the newest tag. The release workflow runs the same check (`make pin-check`, all tags fetched) on the tagged commit and also requires the pin to equal the tag being cut. A tag build without that tag name fails, and so does one without `docs/release-notes/<version>.md`. The image, notes and binary jobs wait for it.
6. Releases are CalVer only (`YY.MM.N`, no `v`). The release workflow fires on CalVer-shaped tags, and its pin job fails on any tag that is not `YY.MM.N`.
7. The release PR adds `docs/release-notes/<version>.md` with what an operator must do before upgrading (`go test ./deploy/` fails without it for the pinned version). The release body is that file, then the notes GitHub generates from the merged PRs.

## Roll back the app

Roll back when the new release breaks something a forward fix cannot cover in
time: sign-in, ingest, alert delivery, or the app does not come up. A failed
`migrate` is not a reason: the deploy stops there with the old app serving
(see [Migrations](#migrations)), fix the cause and rerun.

| Step | What to do |
|---|---|
| 1. Find the previous image | Production: the deploy role's image pin before the release bump, the multi-arch index digest (its git history). Self-host: the previous `ghcr.io/thesada/thesada-app:<version>` in `deploy/docker-compose.yml` |
| 2. Pin it back | Production: revert the pin bump and run the app deploy. Self-host: set the old tag in compose and run `docker compose up -d app` |
| 3. Migrations | Nothing to undo, no down SQL. The old binary's `migrate` skips every version it knows and leaves newer rows alone (`applied_now` 0). Do not run the `Rollback:` SQL in the migration headers: it drops data the next roll forward needs |
| 4. Database image | Leave it. `ALTER EXTENSION timescaledb UPDATE` cannot go back, an older timescaledb image fails on a volume the newer one updated |
| 5. Verify | `/api/v1/version` names the old release, `/api/v1/readyz` is ok, devices show new `last_seen_at`, one test alert arrives |

26.11.4 runs on the 0049 schema: it selects no `*`, and every new column is
nullable or has a default. A migrate run that stopped partway leaves a recorded
prefix the old binary also runs on. Both were checked with an upgrade test on
26.11.4-shaped data before the 26.11.5 release. What 26.11.4 does with data
26.11.5 wrote:

| Migration | Under 26.11.4 |
|---|---|
| 0042 passkeys | No passkey factor. An account whose only second factor is a passkey signs in with password or magic link alone, TOTP accounts keep TOTP. Keys stay stored |
| 0043, 0044 channels | Email goes to the account address, telegram to the account's old chat id column, a webhook to the URL 26.11.5 mirrors into the subscription. A telegram channel or an extra email channel added on 26.11.5 does not deliver (an extra email subscription goes to the account address). The channel on/off switch is not read, so a subscription on a switched-off channel sends again |
| 0047 email confirmation | Not read. Mail goes only to the account address |
| 0045, 0046 trend rules | Not evaluated. No trend alerts, open trend alerts stay open until the new release runs again |
| 0048 open networks, config staleness | The open WiFi markers moved out of the secret store are not seen, device reads are not checked for staleness. How a 26.11.4 config save treats an open network after the move: not verified |
| 0049 `rekeyed` | Rows 26.11.4 writes take the default `false`, right for every write it makes |

Back on the new release later: a subscription 26.11.4 created has no
`channel_id` and does not deliver. List them with `SELECT id, user_id, channel
FROM alert_subscriptions WHERE channel_id IS NULL` and add them again from the
alerts page (not verified as a procedure).

Last resort, when the data itself is damaged: restore the database dump taken
right before the deploy, then pin the old image as above. Everything written
after the dump is lost: telemetry, alerts, accounts, channels, device secrets
and certificates issued since (those devices need a re-pair). The dump only
restores into the same timescaledb version it came from (see
[DB role lockout](#db-role-lockout), step 5). The restore steps belong to the
deploy's backup procedure and are not repeated here.

## One app instance

Run one app container per database. Device write claims, request polls, rate
limits and the alert dispatch claim live in process memory, so a second
instance or a rolling deploy with two replicas overlaps device writes and
sends alerts twice. The list is in `docs/invariants.md`, "The app runs as one
instance". Upgrade by stopping the old container before the new one starts.

## Migrations

`thesada-app migrate` runs as `thesada_app`, the owner of every table. Tenant tables are `FORCE ROW LEVEL SECURITY`, so the owner sees no rows: a data step (`UPDATE` / `INSERT` / `DELETE`) on one switches to the BYPASSRLS role with `SET LOCAL ROLE thesada_app_admin`. Since 0040 that switch needs a membership grant.

1. Once per database, as a superuser, before the first migrate that includes 0040 or later:
   `GRANT thesada_app_admin TO thesada_app;`
2. Check it: `SELECT pg_has_role('thesada_app', 'thesada_app_admin', 'MEMBER');` returns `t`.
3. Without it, 0040 and 0041 fail with `permission denied to set role "thesada_app_admin"` and the deploy stops with the old binary still serving. Grant, then rerun `thesada-app migrate`.
4. An `UPDATE` or `DELETE` without the switch does not fail, it changes 0 rows. An `INSERT` without it fails the RLS `WITH CHECK` policy, which stops the migration with an error. `go test ./migrations/` refuses either (`TestMigrations_RLSDataStepsSetRole`).
5. A migration that creates a table and then writes it as `thesada_app_admin` grants that table to `thesada_app_admin` explicitly (0038, 0043). The default privileges from 0001 cover only tables `thesada_app` creates, so under a superuser migrator (`pkg/db` RLS test, a hand-run `psql`) the data step fails with `permission denied for table`.

## Magic-link mail broken

1. Symptom: users report the sign-in link never arrives; the app still shows "check your email" (the failure is operator-only; the UI still reports success).
2. Check config: an empty `SMTPHost` makes the mailer **drop silently and return success** (`mailer.go:42`) - the link is never sent. Set `SMTPHost`.
3. Check the app logs for `notify send failed` (SMTP handoff errors, a stalled server times out after 30 s) and `notify.link.request_failed` (account or token lookup errors). The send runs after the page answers, so neither shows to the visitor.
4. There is no bounce/delivery tracking - a link that was handed to SMTP but never arrived (greylist/spam) is invisible. Test end-to-end with a known-good mailbox.
5. Workaround while broken: users with a password can still sign in; new users are blocked until mail is restored.

## Alert notification never arrived

1. Find the row (substitute the device uuid from the admin device page): `SELECT id, delivery_status, delivery_attempts, next_attempt_at, delivered_email, delivered_telegram FROM device_alerts WHERE device_pk = '<device-uuid>' ORDER BY id DESC LIMIT 5;`
2. Decode `delivery_status`:
   - `pending` - retries are still running (doubling backoff from `THESADA_ALERT_RETRY_BASE`, default 1m). Check logs for `alert.delivery.retry_scheduled` and the per-channel `alert email failed` / `alert telegram failed` error to fix the channel (SMTP creds, Telegram token, chat_id).
   - `none` - no subscription matched at dispatch time (channel + `min_severity` vs the alert's severity). Not retried automatically; fix the subscription, then re-poke (below) if that alert should still go out - dispatch re-matches subscriptions on every run.
   - `dead` - budget spent (`THESADA_ALERT_MAX_ATTEMPTS`, default 5), logs show `alert.delivery.state_change` to `dead`. Fix the channel first, then re-poke. If that line (or a `retry_scheduled` line) carries `reason: panic`, the dispatch itself crashes on this row: the stack is on the `goroutine.panic` line whose `site` is `alerts.redispatch` or `mqtt.alert_dispatch`. Fix the code before re-poking, or the row burns its budget again.
   - Re-poke (works for `dead` and `none`): `UPDATE device_alerts SET delivery_status='pending', delivery_attempts=0, next_attempt_at=now() WHERE id = <alert-id>;` - the sweeper (every `THESADA_ALERT_REDISPATCH_INTERVAL`, default 1m) picks it up.
   - `delivered` but nothing arrived - the send was handed off (SMTP accepted / Telegram 200); chase the provider side (spam folder, greylisting).
3. Alert row missing entirely: search logs for `alert.ingest.dead_letter` (the insert failed after retries) or for `goroutine.panic` whose `site` is `mqtt.alert_insert_retry` (the retry itself crashed). Both lines carry the full payload for manual replay. Also check the firmware side published at all.
4. Delivery works but repeats: retained alerts are dropped and the same payload inside 10 minutes is refused (`alert dropped, duplicate within window` at debug). A repeat past that is the device publishing again; check its rule cooldown. See [`failure-modes/alerts.md`](failure-modes/alerts.md).

---

Related: [`operator-role.md`](operator-role.md), [`failure-modes/`](failure-modes/), the firmware side [`thesada-fw/docs/runbook.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/runbook.md).
