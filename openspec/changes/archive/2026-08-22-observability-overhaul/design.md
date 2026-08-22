## Context

Ran is a multi-protocol honeypot with 28 trap handlers (TCP + UDP), Prometheus metrics on a custom registry, and structured JSON logging via `slog`. Logs ship to Loki via stdout capture (Promtail/Alloy). The current metrics and logging have grown organically — each trap follows the same `Session` pattern (`LogConnect`/`LogAuthAttempt`/`LogCommand`/`LogPayload`/`LogDisconnect`), but inconsistencies have crept in (SIP uses wrong log method, UDP never calls `LogDisconnect`, CrowdSec uses different field name for IPs).

The custom `prometheus.Registry` intentionally avoids the default registry but also misses the Go/Process collectors that most Go services expose. The CrowdSec alert pipeline has three separate metrics that should be a single funnel.

## Goals / Non-Goals

**Goals:**
- Fix the `ran_active_sessions` gauge leak for UDP protocols
- Make all log events queryable in Loki with consistent field names and bounded label values
- Every session has exactly one `connect` and one `disconnect` log entry
- Track connection outcomes (completed/timeout/error) in both logs and metrics
- Surface internal errors that are currently invisible
- Expose standard Go process metrics and build info
- Model the CrowdSec alert pipeline as a single funnel metric

**Non-Goals:**
- Byte counting per connection (future change, needs `CountingConn` wrapper)
- Unique attacker counting in Prometheus (Loki handles this via `source_ip` field)
- Per-IP or per-credential Prometheus labels (cardinality explosion)
- Loki/Promtail/Alloy configuration
- Dashboard/alerting rule changes
- Changing the `Alerter` interface signature

## Decisions

### 1. Outcome tracking via enum on Session

**Decision**: Add an `Outcome` string field to `Session` with setter methods. `LogDisconnect()` reads it. Default is `"completed"`.

**Why not a parameter on LogDisconnect?** Because the outcome is often determined at a different point than where disconnect happens (e.g., a `SetDeadline` timeout triggers an error in `Read`, but `LogDisconnect` is called in a `defer`). Storing it on the Session lets any code path set it.

**Outcome values** (bounded enum, not a label explosion):
- `completed` — client disconnected normally or handler finished
- `timeout` — session deadline reached
- `error` — read/write/handshake error
- `rejected` — rate limiter rejected (used only in the `rejected` action, not in disconnect)

### 2. UDP PacketHandler interface change

**Decision**: Change `HandlePacket(ctx, src, destPort, data, respond)` to `HandlePacket(ctx, sess, data, respond)` — the Session carries src, destPort, and logger.

**Why?** The current interface doesn't give handlers access to the Session, so they can't call `LogAuthAttempt` correctly (SIP creates a throwaway session). Passing the Session makes the contract explicit: the handler logs through the session, and the UDP base handles lifecycle (connect/disconnect/metrics).

**Migration**: All 4 UDP handlers (dns, ntp, snmp, sip) need signature change. Each is ~5 lines of change.

### 3. LogConnect promoted to Info

**Decision**: `LogConnect()` becomes `Info` level.

**Why?** At the default `Info` level, connections are currently invisible until an auth/command/payload event. A client that connects and immediately disconnects produces only a disconnect log. For a honeypot, every connection is a meaningful event.

**Trade-off**: More log volume. At SIP's 233k connections, this doubles the log lines for SIP. Acceptable because Loki handles volume well and the connect event is critical for analysis.

### 4. Single pipeline metric replaces three CrowdSec metrics

**Decision**: Replace `ran_crowdsec_alerts_total`, `ran_crowdsec_alerts_cached_total`, `ran_crowdsec_alerts_deduplicated_total` with `ran_crowdsec_pipeline_total{protocol, stage}`.

**Stages** (in pipeline order):
1. `received` — Alert() called
2. `cached` — dropped because IP already banned in decision cache
3. `deduplicated` — dropped because same IP+scenario seen within dedup window
4. `queued` — successfully enqueued to channel
5. `dropped` — channel was full
6. `sent` — successfully pushed to LAPI
7. `failed` — LAPI push failed

**Why single metric?** Funnel arithmetic: `rate(pipeline{stage="sent"}) / rate(pipeline{stage="received"})` gives delivery rate. Three separate metrics make this awkward.

**Breaking change**: Existing dashboards/alerts must update. Acceptable because these metrics are new (v0.3.5) with minimal adoption.

### 5. Normalized log messages

**Decision**: Use short, static message strings. Details go exclusively in structured fields.

| action | msg |
|--------|-----|
| connect | `"session started"` |
| disconnect | `"session ended"` |
| auth_attempt | `"credentials captured"` |
| command | `"command received"` |
| payload | `"payload received"` |
| rejected | `"connection rejected"` |
| error | `"internal error"` |

**Why?** Current messages embed variable data (`"ssh auth from 1.2.3.4:54321 user=root"`), duplicating what's in the structured fields. Static messages are cheaper to index and easier to filter in Loki (`|= "session started"`).

### 6. Error observability approach

**Decision**: Add `LogError(errorType, err)` method on Session (or package-level for non-session errors). No separate `ran_errors_total` metric for now — errors are rare and best analyzed in Loki.

**Error types** (bounded):
- `accept_failed` — TCP listener Accept() error
- `parse_failed` — UDP packet parsing error
- `handshake_failed` — TLS/SSH handshake error

**Why no Prometheus counter?** Errors are low-volume and investigative. Loki with `{action="error"}` is the right tool. If volume grows, a counter can be added later without changing the log structure.

### 7. Go/Process collectors and build info

**Decision**: Register `collectors.NewGoCollector()`, `collectors.NewProcessCollector()`, and a custom `ran_build_info` gauge on the existing custom registry in `metrics.New()`.

**`ran_build_info`** labels: `version`, `goversion`. Constant value `1`. Version comes from `main.version` (already set via ldflags). Go version from `runtime.Version()`.

### 8. CrowdSec field rename: "ip" → "source_ip"

**Decision**: Change all CrowdSec log calls from `"ip", ip` to `"source_ip", ip`.

**Why?** Session logs use `source_ip`. CrowdSec logs use `ip`. In Loki, filtering all events for an IP requires checking both fields. Unifying to `source_ip` enables `{app="ran"} | json | source_ip="1.2.3.4"` across all events.

### 9. Transport field on Session

**Decision**: Add `transport` string (`"tcp"` or `"udp"`) to Session base fields, set at construction.

**Why?** Enables Loki queries like `{app="ran"} | json | transport="udp"` to isolate UDP scan traffic from TCP attack traffic. Low cardinality (2 values), high analytical value.

**Implementation**: `NewSession` gets a `transport` parameter. TCP traps pass `"tcp"`, `UDPTrap.readLoop` passes `"udp"`.

## Risks / Trade-offs

**[Log volume increase]** → Promoting `LogConnect` to Info roughly doubles log lines for high-volume UDP protocols. Mitigation: Loki handles this well; the added observability outweighs the storage cost. Users can still set `RAN_LOG_LEVEL=warn` to reduce volume.

**[Breaking metric changes]** → Removing 3 CrowdSec metrics and adding `outcome` label to `ran_connections_total` breaks existing dashboards. Mitigation: These metrics are from v0.3.5 with minimal external adoption. Document the breaking changes in the changelog.

**[UDP PacketHandler interface change]** → All UDP handler implementations must update. Mitigation: Only 4 handlers (dns, ntp, snmp, sip), each requires minimal changes (~5 lines).

**[Outcome accuracy]** → Distinguishing `timeout` from `error` requires inspecting the error from `Read`/`Write` calls. Some errors may be misclassified. Mitigation: `net.Error.Timeout()` reliably identifies deadline-exceeded errors in Go's net package. All other errors default to `error`.

## Migration Plan

1. Implement in a single branch — changes are interdependent
2. Update all 28 trap handlers in one pass (outcome + message normalization)
3. Update 4 UDP handlers for new PacketHandler signature
4. Add deprecation note to CHANGELOG for removed metrics
5. No rollback needed beyond git revert — no data migrations, no external state changes
