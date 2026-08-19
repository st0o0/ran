# Design: CrowdSec Alert Optimization

## Architecture Overview

All three features live inside the `CrowdSecAlerter` struct. The `Alerter` interface and all 30+ trap files remain untouched.

```
                    alerter.Alert(ip, protocol, meta)
                              │
                              ▼
                    ┌───────────────────┐
                    │  Alert() method   │
                    │                   │
                    │  1. decisionCache │── IsBanned(ip)? → skip, debug log
                    │     .IsBanned()   │
                    │                   │
                    │  2. dedup         │── seen(ip|scenario) within window? → skip, debug log
                    │     .Allow()      │
                    │                   │
                    │  3. ch <- msg     │── into buffered channel (unchanged)
                    └────────┬──────────┘
                             │
                             ▼
                    ┌───────────────────┐
                    │  batchWorker()    │  (replaces worker())
                    │                   │
                    │  collects msgs    │
                    │  into []csAlert   │
                    │                   │
                    │  flushes on:      │
                    │   - ticker        │
                    │   - batch full    │
                    │   - channel close │
                    └────────┬──────────┘
                             │
                             ▼
                    ┌───────────────────┐
                    │  flush()          │
                    │                   │
                    │  POST /v1/alerts  │── single POST with []csAlert
                    │  (N alerts)       │
                    │                   │
                    │  on success:      │
                    │  decisionCache    │── MarkBanned(ip, duration) for each
                    │     .MarkBanned() │
                    └───────────────────┘
```

## Component 1: Dedup Filter

### Data Structure

```go
type dedupFilter struct {
    mu      sync.Mutex
    seen    map[string]time.Time  // key → last-allowed timestamp
    window  time.Duration
    nowFunc func() time.Time      // injectable for testing
}
```

**Key format**: `"{ip}|{scenario}"` — e.g. `"158.94.211.16|custom/ran-smtp-trap"`.

The scenario is constructed in `Alert()` as `"custom/ran-" + protocol + "-trap"` (same logic as `push()` today, moved earlier).

### Methods

```go
func newDedupFilter(window time.Duration) *dedupFilter
func (d *dedupFilter) Allow(key string) bool       // true = let through, false = suppress
func (d *dedupFilter) cleanup()                     // remove entries older than 2× window
```

`Allow()` checks if the key exists and the timestamp is within the window. If so, returns `false`. Otherwise, updates the timestamp and returns `true`.

### Cleanup Strategy

A background goroutine runs every `window` duration (e.g. every 5 minutes) and deletes all entries where `now - timestamp > 2 × window`. The 2× factor avoids racing with entries that are about to expire.

With Ran seeing ~10k unique IPs/day in production, the map stays small (tens of thousands of entries, a few MB at most). No LRU needed.

### Disabled State

When `window == 0`, `Allow()` always returns `true` and no cleanup goroutine starts.

### Metrics

New counter: `ran_crowdsec_alerts_deduplicated_total` with label `{protocol}`. Incremented when `Allow()` returns `false`.

## Component 2: Batch Worker

### Replaces Current Worker

Current:
```go
func (a *CrowdSecAlerter) worker() {
    defer a.wg.Done()
    for msg := range a.ch {
        a.push(msg)  // builds 1-element []csAlert, POSTs immediately
    }
}
```

New:
```go
func (a *CrowdSecAlerter) batchWorker() {
    defer a.wg.Done()
    ticker := time.NewTicker(a.batchInterval)
    defer ticker.Stop()
    var batch []alertMsg

    for {
        select {
        case msg, ok := <-a.ch:
            if !ok {
                // channel closed → flush remaining and return
                a.flush(batch)
                return
            }
            batch = append(batch, msg)
            if len(batch) >= a.batchSize {
                a.flush(batch)
                batch = nil
            }
        case <-ticker.C:
            if len(batch) > 0 {
                a.flush(batch)
                batch = nil
            }
        }
    }
}
```

### flush()

Builds `[]csAlert` from `[]alertMsg` (same payload construction as current `push()`, but for N alerts), then does a single `POST /v1/alerts`. On 401, re-authenticates and retries once (same logic as current `push()`).

On success, each IP in the batch is passed to `decisionCache.MarkBanned()`.

Metrics: `ran_crowdsec_alerts_total` is incremented once per alert in the batch (not once per POST), preserving the existing metric semantics.

### Immediate Mode (no batching)

When `batchInterval == 0`, the constructor falls back to the current `worker()` behavior: read one message, push immediately. This preserves existing behavior for users who don't want batching.

Implementation: `batchWorker()` checks `a.batchInterval == 0` — if so, `ticker` is stopped immediately and never fires. `batchSize` defaults to 1 in this mode, so every message triggers an immediate flush.

## Component 3: Decision Cache

### Interface

```go
type DecisionCache interface {
    IsBanned(ip string) bool
    MarkBanned(ip string, duration time.Duration)
}
```

This interface exists to allow a future Option B (active LAPI polling) to replace the implementation without changing any call sites.

### Local Implementation

```go
type localDecisionCache struct {
    mu      sync.RWMutex
    bans    map[string]time.Time  // ip → ban expiry (absolute time)
    nowFunc func() time.Time
}
```

**`IsBanned(ip)`**: Returns `true` if the IP exists in the map and the expiry is in the future. If expired, deletes the entry and returns `false`.

**`MarkBanned(ip, duration)`**: Sets `bans[ip] = now + duration`. For permanent bans (duration 0), uses a far-future sentinel (`time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)`).

### Cleanup

Expired entries are lazily cleaned up on `IsBanned()` lookup. Additionally, the dedup cleanup goroutine sweeps the decision cache too (piggybacks on the same ticker). No separate goroutine needed.

### noop Implementation

When `decisionCacheEnabled == false`:

```go
type noopDecisionCache struct{}
func (noopDecisionCache) IsBanned(string) bool               { return false }
func (noopDecisionCache) MarkBanned(string, time.Duration)   {}
```

### Metrics

New counter: `ran_crowdsec_alerts_cached_total` with label `{protocol}`. Incremented when `IsBanned()` returns `true` in the `Alert()` path.

## Changes to CrowdSecAlerter Struct

```go
type CrowdSecAlerter struct {
    // --- existing fields (unchanged) ---
    alertsURL   string
    loginURL    string
    machineID   string
    password    string
    banDuration string
    logger      *slog.Logger
    metrics     *metrics.Metrics
    client      *http.Client
    mu          sync.RWMutex
    token       string
    tokenExpiry time.Time
    ch          chan alertMsg
    stopCh      chan struct{}
    wg          sync.WaitGroup

    // --- new fields ---
    dedup          *dedupFilter
    decisionCache  DecisionCache
    batchInterval  time.Duration
    batchSize      int
    banDurationRaw time.Duration   // needed by decision cache (original time.Duration, not formatted string)
}
```

## Changes to NewCrowdSec Constructor

The constructor signature grows to accept the new config values:

```go
func NewCrowdSec(
    url, machineID, password string,
    banDuration time.Duration,
    dedupWindow time.Duration,
    batchInterval time.Duration,
    batchSize int,
    decisionCacheEnabled bool,
    logger *slog.Logger,
    m *metrics.Metrics,
) (*CrowdSecAlerter, error)
```

Alternative: pass a struct instead of individual parameters. Given that we're at 10 params, an options struct is cleaner:

```go
type CrowdSecConfig struct {
    URL           string
    MachineID     string
    Password      string
    BanDuration   time.Duration
    DedupWindow   time.Duration
    BatchInterval time.Duration
    BatchSize     int
    DecisionCache bool
}

func NewCrowdSec(cfg CrowdSecConfig, logger *slog.Logger, m *metrics.Metrics) (*CrowdSecAlerter, error)
```

This also simplifies `run.go` wiring and future config additions.

## Changes to Alert() Method

```go
func (a *CrowdSecAlerter) Alert(_ context.Context, ip string, protocol string, meta map[string]string) {
    scenario := "custom/ran-" + protocol + "-trap"

    if a.decisionCache.IsBanned(ip) {
        a.logger.Debug("alert skipped, ip banned", "ip", ip, "protocol", protocol)
        a.metrics.CrowdSecCached.WithLabelValues(protocol).Inc()
        return
    }

    key := ip + "|" + scenario
    if !a.dedup.Allow(key) {
        a.logger.Debug("alert deduplicated", "ip", ip, "protocol", protocol)
        a.metrics.CrowdSecDeduped.WithLabelValues(protocol).Inc()
        return
    }

    select {
    case a.ch <- alertMsg{IP: ip, Protocol: protocol, Meta: meta}:
    default:
        a.logger.Warn("alert channel full, dropping", "ip", ip, "protocol", protocol)
    }
}
```

**Filter order**: Decision cache first (cheapest — single map lookup), then dedup (slightly more expensive — lookup + potential write). This avoids updating dedup state for already-banned IPs.

## Config Changes

New fields in `config.Config`:

```go
CrowdSecDedupWindow   time.Duration  // RAN_CROWDSEC_DEDUP_WINDOW, default 5m
CrowdSecBatchInterval time.Duration  // RAN_CROWDSEC_BATCH_INTERVAL, default 10s
CrowdSecBatchSize     int            // RAN_CROWDSEC_BATCH_SIZE, default 50
CrowdSecDecisionCache bool           // RAN_CROWDSEC_DECISION_CACHE, default true
```

Parsing: `DedupWindow` and `BatchInterval` use the existing `e.duration()` helper. `BatchSize` uses `e.intMin()` with min=1. `DecisionCache` uses `e.boolean()`.

## New Metrics

Two new counters in `metrics.Metrics`:

```go
CrowdSecDeduped *prometheus.CounterVec  // ran_crowdsec_alerts_deduplicated_total {protocol}
CrowdSecCached  *prometheus.CounterVec  // ran_crowdsec_alerts_cached_total {protocol}
```

The existing `ran_crowdsec_alerts_total` keeps its meaning: alerts actually sent to LAPI. The new counters track what was filtered *before* sending.

## Concurrency Model

```
Goroutines (currently 2, becomes 3):

1. refreshLoop()     — unchanged, refreshes JWT token
2. batchWorker()     — replaces worker(), drains channel into batches
3. cleanupLoop()     — NEW, periodic dedup + decision cache cleanup

Locking:
- dedup.mu           — Mutex, held briefly for Allow() and cleanup()
- decisionCache.mu   — RWMutex, RLock for IsBanned(), Lock for MarkBanned()/cleanup()
- a.mu               — unchanged, protects token (RWMutex)

No lock nesting required — each lock protects independent state.
```

## Close() Behavior

```go
func (a *CrowdSecAlerter) Close() {
    close(a.stopCh)    // signals refreshLoop + cleanupLoop to exit
    close(a.ch)        // signals batchWorker to flush remaining + exit
    // ... wait with timeout (unchanged)
}
```

The `batchWorker()` flushes any remaining alerts in the batch before returning — same graceful drain behavior as today.

## Testing Strategy

All new components are independently testable:

- **dedupFilter**: unit tests with injected `nowFunc`, no HTTP needed
- **localDecisionCache**: unit tests with injected `nowFunc`, no HTTP needed
- **batchWorker/flush**: integration tests with `httptest.Server`, verify:
  - Multiple alerts arrive in a single POST
  - Flush on ticker, flush on batch full, flush on close
- **Alert() filtering**: integration test with dedup + cache, verify suppression
- **Config parsing**: table-driven tests for new env vars

Existing tests continue to work — they test the alert format and auth, which are unchanged. The constructor call changes (struct instead of args), so test helper functions need updating.
