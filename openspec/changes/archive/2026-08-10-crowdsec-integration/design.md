## Context

Rán logs attacker credentials but doesn't trigger automated bans. The homelab stack already runs CrowdSec with a Caddy bouncer. Rán needs to push alerts to CrowdSec's LAPI so attackers are banned across all sites instantly.

## Goals / Non-Goals

**Goals:**
- Instant ban on any honeypot auth_attempt via CrowdSec LAPI push
- Non-blocking: alert failures must never affect trap operation
- Separate scenarios per protocol for granular CrowdSec visibility
- Configurable ban duration (including permanent via `0`)
- Observable via Prometheus metrics (success/failure counts)

**Non-Goals:**
- CrowdSec Go SDK dependency (raw HTTP POST is sufficient)
- Log-based acquisition (explored and deferred — push is better for instant bans)
- CrowdSec Hub package publishing (can be done later)
- Receiving decisions from CrowdSec (Rán only pushes, never queries)

## Decisions

### 1. Alerter interface for loose coupling
```go
type Alerter interface {
    Alert(ctx context.Context, ip string, protocol string)
}
```
CrowdSec is one implementation. A no-op `Alerter` is used when `RAN_CROWDSEC=off`. This keeps traps decoupled — they call `alerter.Alert()` without knowing what happens. Testable with a mock.

### 2. Buffered channel + single worker goroutine
Traps send to a buffered channel (capacity 256). A single worker goroutine drains the channel and makes HTTP POSTs sequentially. If the channel is full, alerts are dropped with a warning log. This guarantees traps never block on CrowdSec.

### 3. Self-contained decisions in alerts
Rán sends alerts with embedded decisions (ban type, duration, IP scope). CrowdSec doesn't need a local scenario to evaluate — it forwards the decision directly to bouncers. This is simpler and faster than making CrowdSec evaluate its own rules.

### 4. Per-protocol scenario names
- `custom/ran-ssh-trap`
- `custom/ran-http-trap`
- `custom/ran-mysql-trap`

Separate scenarios give granular visibility in CrowdSec dashboards and community blocklists. Other CrowdSec users can subscribe to specific trap types.

### 5. Ban duration via `RAN_CROWDSEC_BAN_DURATION`
Default: `4h`. Supports Go duration strings. Special value `0` means permanent ban. A honeypot hit is always malicious, so even permanent is defensible — but 4h is a safe default that resolves false positives (misconfigured scanners, researchers).

### 6. No CrowdSec Go SDK
The LAPI alert endpoint is a simple JSON POST with an API key header. ~100 lines of Go, no external dependency beyond `net/http`. The alert JSON struct is defined inline.

### 7. Graceful shutdown drains the alert channel
On shutdown, the worker processes remaining alerts in the channel (up to a 5-second timeout) before exiting. This ensures alerts from the last connections aren't lost.

## Risks / Trade-offs

- **CrowdSec LAPI unavailable** → Alerts are dropped silently (logged at warn). Traps continue normally. The `ran_crowdsec_alerts_total{status="failure"}` metric surfaces this.
- **Channel overflow under heavy load** → 256-capacity buffer handles bursts. Under sustained heavy load (>256 concurrent auth_attempts faster than LAPI response time), some alerts are dropped. Acceptable — CrowdSec bans the IP on the first alert anyway.
- **API key in env var** → Same pattern as every other secret in the stack. Docker Compose secrets or `.env` file.
