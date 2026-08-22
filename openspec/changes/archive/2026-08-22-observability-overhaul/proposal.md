## Why

Ran's observability has critical gaps: the `ran_active_sessions` gauge leaks for UDP protocols (incremented but never decremented), SIP auth attempts bypass the standard `action=auth_attempt` logging path making Loki queries incomplete, and field naming inconsistencies (`ip` vs `source_ip`) prevent reliable cross-component filtering. Additionally, the custom Prometheus registry lacks Go process/runtime collectors, there's no build info metric, connection outcomes aren't tracked, and internal errors are invisible. These gaps make it impossible to build reliable dashboards or answer basic operational questions like "is a listener down or just quiet?" or "how many unique attackers hit us?"

## What Changes

- **Fix UDP session lifecycle**: call `LogDisconnect()` and ensure `RecordEnd()` is called consistently after packet handling, fixing the `ran_active_sessions` gauge leak
- **Fix SIP auth categorization**: use `LogAuthAttempt()` instead of `LogPayload("auth_attempt")` so SIP auth events appear under `action=auth_attempt`
- **Normalize field names**: rename CrowdSec's `"ip"` field to `"source_ip"` for consistency with session logs
- **Promote `LogConnect()` to Info level**: connections are events worth seeing at default log level
- **Add `transport` field**: `tcp` or `udp` on all session base fields
- **Add `outcome` tracking**: `completed`, `timeout`, `error` on disconnect events and as a Prometheus label
- **Add `action=rejected`**: structured rejection events with `protocol`, `transport`, `dest_port`
- **Add `action=error`**: internal error events with `error_type` for accept failures, parse failures, handshake errors
- **Log UDP parse failures**: silent `return` statements become structured error logs
- **Normalize log messages**: consistent short messages ("session started", "session ended", "credentials captured", etc.) with details only in structured fields
- **Register Go/Process collectors**: add `GoCollector` and `ProcessCollector` to the custom registry for `process_start_time_seconds`, `go_goroutines`, etc.
- **Add `ran_build_info`**: info metric with version, Go version
- **Add `ran_crowdsec_alerts_dropped_total`**: counter for channel-full alert drops
- **BREAKING**: Replace three separate CrowdSec metrics with `ran_crowdsec_pipeline_total{protocol, stage}` where stage ∈ {received, cached, deduplicated, queued, sent, failed, dropped}
- **BREAKING**: Add `outcome` label to `ran_connections_total{protocol, outcome}`

## Capabilities

### New Capabilities
- `structured-logging`: Consistent structured log events with normalized actions, messages, and fields across all protocols and components — designed for Loki label extraction and querying
- `connection-outcomes`: Track how sessions end (completed/timeout/error) in both logs and Prometheus metrics
- `error-observability`: Surface internal errors (accept failures, parse errors, handshake failures) as structured log events and Prometheus counters

### Modified Capabilities
- `metrics`: Add Go/Process collectors, `ran_build_info`, `outcome` label on `ran_connections_total`, replace three CrowdSec metrics with pipeline funnel metric, add `ran_crowdsec_alerts_dropped_total`
- `crowdsec-alerter`: Rename `"ip"` to `"source_ip"` in logs, add pipeline stage logging, add dropped alert counter
- `udp-trap-base`: Fix session lifecycle — call `LogDisconnect()` after packet handling, pass Session to `PacketHandler`

## Impact

- **`internal/metrics/metrics.go`**: New metrics, Go/Process collectors, label changes
- **`internal/trap/trap.go`**: `Session` struct changes (transport, outcome), `LogConnect` level change, `LogDisconnect` gains outcome param, new `LogRejected`/`LogError` methods, normalized messages
- **`internal/trap/udp.go`**: `PacketHandler` interface change (receives Session), `LogDisconnect` call added
- **All 28 trap handlers**: Pass outcome to `LogDisconnect`, adapt UDP handlers to new `PacketHandler` signature
- **`internal/trap/sip.go`**: Replace `LogPayload("auth_attempt")` with `LogAuthAttempt()`
- **`internal/alert/crowdsec.go`**: `"ip"` → `"source_ip"`, pipeline metrics, dropped counter
- **`cmd/ran/main.go`**: Pass version/goversion to metrics, register collectors
- **Dashboards/Alerts**: Existing PromQL queries referencing removed CrowdSec metrics or `ran_connections_total` without `outcome` label will break
