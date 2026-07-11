# Failure modes: alert ingest + delivery (app)

`failure -> detection -> recovery` for device -> app ingest and app -> notification-channel delivery (`pkg/mqtt/mqtt_ingest.go`, `pkg/alerts/alerts.go`). The firmware publish side is [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md). A blank recovery cell is a gap.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| MQTT broker down | `mqtt.connection.state_change` logs + `/readyz` degrades | **Automatic:** `SetAutoReconnect` + `SetConnectRetry`, 5s; `OnConnect` re-subscribes (`mqtt.go`) |
| Malformed alert (non-JSON / bad severity) | `slog.Warn("alert parse failed")` / `"alert dropped: bad or missing severity"` (`mqtt_ingest.go`) | None (fix firmware contract) |
| Alert from unknown device | `slog.Debug("alert from unknown device ignored")` (`mqtt_ingest.go`) - near-silent | Device must publish `info` first |
| Alert DB insert fails | `slog.Warn("alert insert failed, retrying...")`; final `alert.ingest.dead_letter` at error with full payload | **Automatic:** 3 background retries (5s/15s/45s, 64-slot cap); then manual replay from the dead-letter log line. MQTT QoS 1 redelivers on reconnect |
| Notification send fails (SMTP/Telegram down, channel unconfigured) | Per-channel `slog.Error(...)`; `alert.delivery.retry_scheduled` at warn (`alerts.go`) | **Automatic:** row stays `pending`, redispatch sweeper retries with doubling backoff (base `THESADA_ALERT_RETRY_BASE`, default 1m) until delivered or budget spent |
| All channels keep failing | `alert.delivery.state_change` to `dead` at error, after `THESADA_ALERT_MAX_ATTEMPTS` (default 5) | Operator fixes channel, then manual re-poke (set `delivery_status='pending'`, rewind `next_attempt_at`) |
| Process death between insert and dispatch | Row left `delivery_status='pending'` | **Automatic:** startup sweep redispatches every pending-and-due row (`redispatch.go`) |
| Handler panic | Recovered at dispatch point -> `slog.Error("mqtt.callback_panic")` (`mqtt.go`) | One bad message can't crash ingest |

## Gaps

- **No ingest lag / queue-depth metric** (`mqtt.go`).
- **Insert dead-letter is log-only.** Until the insert lands the alert exists only in process memory; a crash mid-retry loses it (reconstructable from the `alert.ingest.dead_letter` payload only if the final log line fired).
- **Channel success is per-alert, not per-recipient.** Two email subscribers, one send fails: the channel counts delivered and the failed recipient is not retried (`alerts.go::Dispatch`).
- **`dead` alerts are operator-visible only (logs/DB).** No UI surface for delivery state yet; the end user still cannot see that their alert never went out.
- **Sweeper claim is in-process.** Running more than one app instance can double-send; needs `FOR UPDATE SKIP LOCKED` claims first (`alerts.go::claim`).
- **No duplicate-alert detection.** QoS 1 (at-least-once), `InsertAlert` has no dedup key (`alert.go`), and `handleAlert` discards the retained flag (`_ = retained`, `mqtt_ingest.go`) - a retained alert re-ingests into a new row and re-notifies on every app reconnect.

---

Related: [`../operator-role.md`](../operator-role.md), the fw side [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md), [`../security-review-checklist.md`](../security-review-checklist.md).
