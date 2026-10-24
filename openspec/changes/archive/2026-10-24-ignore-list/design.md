## Context

The sensor is the only component that decides what becomes an alert, so the ignore list lives there. Traps only need to know whether a session is ignored to mark their log lines and count the metric.

## Decisions

- **Parse once at config load.** `config.ParseIgnoreList` returns normalized `[]netip.Prefix`: bare addresses become host prefixes, CIDRs are masked, IPv4-mapped IPv6 entries become IPv4, duplicates are dropped. Empty entries and whitespace are skipped like in `RAN_TRAPS`. Zones and mapped prefixes shorter than `/96` are rejected.
- **Match on the socket peer.** `Sensor.Ignored(ip)` unmaps the address and checks the prefixes. With PROXY protocol the peer is the header address, as everywhere else.
- **Sensor entry points.** `Alert` returns an empty class and `SessionEnd` returns false for an ignored source, so nothing reaches `classify`, `touchScan`, the sink or the probe log; `touchScan` also refuses ignored sources as defense in depth. `SessionEnd` returning false makes the caller log the session itself, which keeps per-session lines for ignored probes.
- **Session marker.** `Session.UseSensor` asks the sensor (optional `Ignored` method) and, if true, adds `ignored=true` to the session logger. `RecordStart` increments `ran_ignored_sessions_total{protocol}` once per session (label set is the protocol names). Sessions rejected by the limiter never become sessions and are not counted there; they appear in `ran_sessions_rejected_total`.
- **UDP.** UDP traps have no alerter, so they use the `Config.IgnoreIPs` list directly: log marker and metric only. Nothing else changes, because UDP never alerts.
- **No pipeline stage.** The proposal planned a stage `ignored` in `ran_crowdsec_pipeline_total`. The stages describe what the CrowdSec sink did with an event it received; ignored sessions are dropped in the sensor before the sink, and the sink may not exist (`RAN_CROWDSEC=off`). A stage counted outside the sink would break the per-stage accounting, so it is not added. `ran_ignored_sessions_total` is the signal.
- **Limits unchanged.** The limiter runs before the session exists and keys on the host, so ignored sources count against `RAN_MAX_SESSIONS` and `RAN_MAX_PER_IP`.

## Risks

- A wide range (for example `0.0.0.0/0`) silences all alerts; this is the operator's explicit choice and is visible in the startup log.
