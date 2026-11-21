# Failure modes: alert ingest + delivery (app)

`failure -> detection -> recovery` for device -> app ingest and app -> notification-channel delivery (`pkg/mqtt/mqtt_ingest.go`, `pkg/alerts/alerts.go`). The firmware publish side is [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md). A blank recovery cell is a gap.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| MQTT broker down | `mqtt.connection.state_change` logs + `/readyz` degrades | **Automatic:** `SetAutoReconnect` + `SetConnectRetry`, 5s; `OnConnect` re-subscribes (`mqtt.go`) |
| Malformed alert (non-JSON / bad severity) | `slog.Warn("alert parse failed")` / `"alert dropped: bad or missing severity"` (`mqtt_ingest.go::handleAlert`, classified by `parseAlert`) | None (fix firmware contract). The visual rules editor publishes `{"severity":"warn","code":<rule key>,"message":<text>}` with both strings JSON-escaped and cut to fit 255 bytes, the device offline queue slot. Checked by `pkg/mqtt/blockly_alert_test.go` |
| Alert from unknown device | `slog.Debug("alert from unknown device ignored")` (`mqtt_ingest.go`) - near-silent | Device must publish `info` first |
| Alert DB insert fails | `slog.Warn("alert insert failed, retrying...")`; final `alert.ingest.dead_letter` at error with full payload | **Automatic:** 3 background retries (5s/15s/45s, 64-slot cap); then manual replay from the dead-letter log line. MQTT QoS 1 redelivers on reconnect |
| Notification send fails (SMTP/Telegram down, channel unconfigured) | Per-channel `slog.Error(...)`; `alert.delivery.retry_scheduled` at warn (`alerts.go`) | **Automatic:** row stays `pending`, redispatch sweeper retries with doubling backoff (base `THESADA_ALERT_RETRY_BASE`, default 1m) until delivered or budget spent |
| All channels keep failing | `alert.delivery.state_change` to `dead` at error, after `THESADA_ALERT_MAX_ATTEMPTS` (default 5) | Operator fixes channel, then manual re-poke (set `delivery_status='pending'`, rewind `next_attempt_at`) |
| Process death between insert and dispatch | Row left `delivery_status='pending'` | **Automatic:** startup sweep redispatches every pending-and-due row (`redispatch.go`) |
| Handler panic | Recovered at dispatch point -> `slog.Error("mqtt.callback_panic")` (`mqtt.go`) | One bad message can't crash ingest |
| Panic in the insert retry, the inline dispatch or a redispatch row | `goroutine.panic` at error with `site` (`mqtt.alert_insert_retry`, `mqtt.alert_dispatch`, `alerts.redispatch`) and the stack (`pkg/safego`) | **Automatic** for dispatch: the panic counts as one attempt, channels that sent are kept, and the sweep retries after backoff until `dead` at `THESADA_ALERT_MAX_ATTEMPTS`. The retry panic line carries the dead-letter fields for a manual replay |
| Retained sensor replay at app restart | `slog.Debug("sensor ignored, retained replay")` (`mqtt_ingest.go`) | None needed: a replay neither bumps `last_seen_at` nor clears an open absence alert |
| Trend rule check fails on ingest | `slog.Error("trend evaluate failed")` (`mqtt_ingest.go::evaluateTrends`), per-rule `alert.trend.insert_failed` or `alert.trend.clear_failed` | The reading is already stored. The next reading checks again, so a missed raise or clear catches up on the next sample |
| No baseline for a trend rule (device was quiet for two windows) | None, by design | No decision is taken: a long silence never reads as a jump. The next sample a window after the gap decides again |

## Gaps

- **No ingest lag / queue-depth metric** (`mqtt.go`).
- **Insert dead-letter is log-only.** Until the insert lands the alert exists only in process memory. A process crash mid-retry loses it. A replay needs the payload from the `alert.ingest.dead_letter` line or the `mqtt.alert_insert_retry` `goroutine.panic` line, so it works only if one of them fired.
- **A switched-off channel is skipped, not queued.** An alert while a channel is off never reaches it, switching it on later does not replay (`alerts.go::loadRecipients`).
- **Channel success is per-alert, not per-recipient.** Two email subscribers, one send fails: the channel counts delivered and the failed recipient is not retried (`alerts.go::Dispatch`).
- **`dead` alerts are operator-visible only (logs/DB).** No UI surface for delivery state yet; the end user still cannot see that their alert never went out.
- **A panic while loading the row is not counted.** Only a render or send panic counts as an attempt. One in the tenant-scoped row load leaves the row due without backoff, so the sweep retries it each pass (`alerts.go::Dispatch`).
- **Sweeper claim is in-process.** Running more than one app instance can double-send; needs `FOR UPDATE SKIP LOCKED` claims first (`alerts.go::claim`).
- **The device Telegram relay is not an alert.** `Telegram.broadcast` on the device also publishes `{"value":"<text> [heap=N]"}` to `<prefix>/alert` (`TelegramModule::send` through the EventBus). It has no severity, so `handleAlert` drops it. The stored alert is the rule's own JSON publish.
- **Trend rules see only live readings.** A rule added now does not look back over stored telemetry, and a reading that arrives late (buffered on the device) is compared with the baseline at its arrival time, not its measurement time (`trend_rules.go`).
- **Duplicate detection is a window, not a key.** `InsertAlert` refuses the same JSON payload from the same device inside 10 minutes (`alert.go`), and `handleAlert` drops a retained alert outright (`mqtt_ingest.go`). That covers QoS 1 redelivery, retained replay on reconnect, and the insert retry after a lost commit-ack. It does not cover a genuine repeat with an identical payload inside the window (firmware rule cooldowns are 15 minutes, so none in the shipped examples), and the firmware sends no sequence number to key on.

---

Related: [`../operator-role.md`](../operator-role.md), the fw side [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md), [`../security-review-checklist.md`](../security-review-checklist.md).
