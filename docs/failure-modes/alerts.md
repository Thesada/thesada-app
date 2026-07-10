# Failure modes: alert ingest + delivery (app)

`failure -> detection -> recovery` for device -> app ingest and app -> notification-channel delivery (`pkg/mqtt/mqtt_ingest.go`, `pkg/alerts/alerts.go`). The firmware publish side is [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md). A blank recovery cell is a gap.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| MQTT broker down | See gap - no handler, no metric | **Automatic:** `SetAutoReconnect` + `SetConnectRetry`, 5s; `OnConnect` re-subscribes (`mqtt.go:94`) |
| Malformed alert (non-JSON / bad severity) | `slog.Warn("alert parse failed")` / `"alert dropped: bad or missing severity"` (`mqtt_ingest.go:127`) | None (fix firmware contract) |
| Alert from unknown device | `slog.Debug("alert from unknown device ignored")` (`mqtt_ingest.go:151`) - near-silent | Device must publish `info` first |
| Notification channel not configured | Per-channel `slog.Error(...)` (`alerts.go:136`) | Operator sets token/SMTP |
| Handler panic | Recovered at dispatch point -> `slog.Error("mqtt.callback_panic")` (`mqtt.go:215`) | One bad message can't crash ingest |

## Gaps

- **Broker disconnect is fully silent.** No `SetConnectionLostHandler`/`SetReconnectingHandler`, no metric; `/healthz` returns static `{"status":"ok"}` regardless of broker/DB (`mqtt.go:88`, `api.go:72`). Auto-reconnect works, but you can't see an outage.
- **No ingest lag / queue-depth metric** (`mqtt.go:97`).
- **Failed alert DB insert is lost.** `slog.Error("alert insert failed")` (`mqtt_ingest.go:159`) - no retry, no dead-letter.
- **No notification-delivery retry / dead-letter / startup redispatch.** A failed email/Telegram send is logged and abandoned; `markDelivered` only runs if >=1 channel succeeded (`alerts.go:143`). Dispatch is fire-and-forget `go n.Dispatch(...)` (`mqtt_ingest.go:167`); a process death mid-alert leaves it permanently undelivered - confirmed no sweeper of `delivered_*=false` rows exists.
- **All-channels-fail is never surfaced to the user.** `alert.delivery.state_change` is guarded by `emailOK||tgOK` (`alerts.go:143`) - the user is never notified their alert didn't go out; only operator logs show it.
- **No duplicate-alert detection.** QoS 1 (at-least-once), `InsertAlert` has no dedup key (`alert.go:39`), and `handleAlert` discards the retained flag (`_ = retained`, `mqtt_ingest.go:156`) - a retained alert re-ingests into a new row and re-notifies on every app reconnect.

---

Related: [`../operator-role.md`](../operator-role.md), the fw side [`thesada-fw/docs/failure-modes/alerts.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/alerts.md), [`../security-review-checklist.md`](../security-review-checklist.md).
