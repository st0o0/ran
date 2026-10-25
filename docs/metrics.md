# Metrics


| Variable | Default | Purpose |
|---|---|---|
| `RAN_METRICS_ADDR` | `:9550` | Prometheus metrics listen address (a single `host:port`; also serves `/healthz`) |

Exposed metrics, besides `ran_build_info{version,goversion}` and the standard Go
runtime and process collectors:

- `ran_connections_total{protocol,outcome}`: connection counter. Outcomes: `completed`, `timeout`, `error`, `too_long` (line over the read limit), `probe` (the client did not speak the protocol)
- `ran_credentials_captured_total{protocol}`: credential capture counter
- `ran_active_sessions{protocol}`: active session gauge
- `ran_session_duration_seconds{protocol}`: session duration histogram (buckets 0.1 s to 120 s)
- `ran_crowdsec_alerts_dropped_total{protocol}`: alerts dropped because the delivery queue was full
- `ran_panics_recovered_total{protocol}`: panics recovered at connection and packet boundaries
- `ran_proxy_protocol_dropped_total{protocol}`: connections closed by the PROXY protocol listener (untrusted peer, no valid header, deadline, handshake limit, stalled consumer)
- `ran_udp_rate_limited_total{protocol}`: UDP packets dropped by the packet rate limiter
- `ran_sessions_rejected_total{protocol}`: TCP connections and UDP packets rejected by the session limiter (`RAN_MAX_SESSIONS`, `RAN_MAX_PER_IP`)
- `ran_probe_summary_suppressed_sessions_total`: probe sessions whose per-session log lines were replaced by a summary
- `ran_ignored_sessions_total{protocol}`: sessions from sources in `RAN_IGNORE_IPS` (served and logged, never alerted; also counted in `ran_connections_total`)
- `ran_connections_rejected_total{reason}`: TCP connections closed at accept time before a session existed; `reason` is `shun` (`RAN_SHUN`), the only value
- `ran_shun_active_sources`: sources currently inside a shun window
- `ran_tracked_entries{map}`: entries in the bounded tracking maps (`map`: `scan`, `probe`, `cooldown`, `offender`)
- `ran_tracked_evictions_total{map}`: live entries evicted because a map was full; a rising rate means `RAN_CROWDSEC_MAX_TRACKED` is too small
- `ran_crowdsec_push_duration_seconds`: histogram of CrowdSec LAPI push request durations
- `ran_crowdsec_push_errors_total`: failed LAPI pushes (transport errors, non-2xx answers and failed re-logins after a 401)
- `ran_crowdsec_queue_length`: alerts waiting in the send queue
- `ran_crowdsec_pipeline_total{protocol,stage}`: CrowdSec alert pipeline events. Stages: `received`, `invalid` (rejected source address), `closed` (raised after shutdown), `filtered` (class not in `RAN_BAN_ON`), `cooldown` (within `RAN_ALERT_COOLDOWN`), `queued`, `dropped`, `sent`, `failed`, `released` (cooldown slot freed after a failed push, so the source is reported again). The 0.3.x stages `cached` and `deduplicated` no longer exist. Per-class counts are not a label (cardinality); the class is in the alert meta and the logs.

