# Third-party licenses

This project is licensed AGPL-3.0-only (see `LICENSE`). The following
third-party Go modules ship in compiled binaries; each is used under
the licence terms noted below. All are compatible with AGPL-3.0.

## Direct dependencies

| Module | Version range | Licence | Selected terms |
|---|---|---|---|
| `github.com/coreos/go-oidc/v3` | v3.x | Apache-2.0 | as published |
| `github.com/eclipse/paho.mqtt.golang` | v1.5.x | EPL-2.0 OR EDL-1.0 | **EDL-1.0 selected** (BSD-3-Clause equivalent, AGPL-compatible) |
| `github.com/go-jose/go-jose/v4` | v4.x | Apache-2.0 | as published |
| `github.com/google/uuid` | v1.x | BSD-3-Clause | as published |
| `github.com/gorilla/websocket` | v1.5.x | BSD-2-Clause | as published |
| `github.com/jackc/pgx/v5` | v5.x | MIT | as published |
| `github.com/jackc/pgpassfile` | v1.x | MIT | as published |
| `github.com/jackc/pgservicefile` | v0.x | MIT | as published |
| `github.com/jackc/puddle/v2` | v2.x | MIT | as published |
| `golang.org/x/crypto` | v0.x | BSD-3-Clause | as published |
| `golang.org/x/net` | v0.x | BSD-3-Clause | as published |
| `golang.org/x/oauth2` | v0.x | BSD-3-Clause | as published |
| `golang.org/x/sync` | v0.x | BSD-3-Clause | as published |
| `golang.org/x/text` | v0.x | BSD-3-Clause | as published |

## Vendored frontend assets

The HTML templates load JS assets vendored under
`pkg/web/static/vendor/`:

| Asset | Version | Licence |
|---|---|---|
| htmx | as vendored | BSD-2-Clause |
| Chart.js | as vendored | MIT |

## Notes

- The **Eclipse Paho MQTT Go client** is offered under two licences. We
  use it under the **Eclipse Distribution License v1.0** (a BSD-3-Clause
  equivalent), not EPL-2.0. This is declared in code via a comment at
  the only import site (`pkg/mqtt/mqtt.go`).
- AGPL §13 obligates network operators of this software to share their
  modifications with users who interact with the running service. The
  third-party licences above do not impose that obligation; only the
  AGPL portion of the combined work does.
- No GPL / LGPL / MPL / SSPL dependencies are linked. Adding any in
  future requires a re-check that the combined work stays compatible.
