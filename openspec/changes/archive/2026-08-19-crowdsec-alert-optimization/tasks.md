# Tasks: CrowdSec Alert Optimization

## Phase 1: Foundation

### Task 1.1: Introduce CrowdSecConfig struct
- [x] Create `CrowdSecConfig` struct in `internal/alert/crowdsec.go` with all fields (existing + new)
- [x] Change `NewCrowdSec` signature to accept `CrowdSecConfig` instead of individual params
- [x] Update `cmd/ran/run.go` to construct and pass `CrowdSecConfig`
- [x] Update all test helpers to use new constructor signature
- [x] Verify existing tests pass

**Files**: `internal/alert/crowdsec.go`, `internal/alert/crowdsec_test.go`, `cmd/ran/run.go`

### Task 1.2: Add new config fields
- [x] Add `CrowdSecDedupWindow` (duration, default 5m) to `config.Config`
- [x] Add `CrowdSecBatchInterval` (duration, default 10s) to `config.Config`
- [x] Add `CrowdSecBatchSize` (intMin, default 50, min 1) to `config.Config`
- [x] Add `CrowdSecDecisionCache` (boolean, default true) to `config.Config`
- [x] Add config tests for new env vars (valid values, defaults, invalid values)
- [x] Wire new config fields into `CrowdSecConfig` in `cmd/ran/run.go`

**Files**: `internal/config/config.go`, `internal/config/config_test.go`, `cmd/ran/run.go`

### Task 1.3: Add new metrics
- [x] Add `CrowdSecDeduped` counter (`ran_crowdsec_alerts_deduplicated_total`, labels: `{protocol}`)
- [x] Add `CrowdSecCached` counter (`ran_crowdsec_alerts_cached_total`, labels: `{protocol}`)
- [x] Register both in `metrics.New()`

**Files**: `internal/metrics/metrics.go`

## Phase 2: Dedup Filter

### Task 2.1: Implement dedupFilter
- [x] Create `dedupFilter` struct with `seen map[string]time.Time`, `window`, `mu`, `nowFunc`
- [x] Implement `newDedupFilter(window)` constructor
- [x] Implement `Allow(key string) bool` — returns true if key is new or window expired, updates timestamp
- [x] Implement `cleanup()` — removes entries older than 2× window
- [x] Disabled behavior: `window == 0` → `Allow()` always returns true
- [x] Unit tests: allow first, suppress duplicate, allow after window expires, cleanup removes stale, disabled mode

**Files**: `internal/alert/dedup.go`, `internal/alert/dedup_test.go`

### Task 2.2: Integrate dedup into CrowdSecAlerter
- [x] Add `dedup *dedupFilter` field to `CrowdSecAlerter`
- [x] Initialize in `NewCrowdSec` from `cfg.DedupWindow`
- [x] Construct scenario string in `Alert()` method: `"custom/ran-" + protocol + "-trap"`
- [x] Check `dedup.Allow(ip + "|" + scenario)` before sending to channel
- [x] Increment `CrowdSecDeduped` metric on suppression
- [x] Debug-log suppressed alerts
- [x] Start cleanup goroutine (add to `wg`, respect `stopCh`)
- [x] Integration test: send same IP+protocol 10 times, verify only 1 reaches the server

**Files**: `internal/alert/crowdsec.go`, `internal/alert/crowdsec_test.go`

## Phase 3: Batching

### Task 3.1: Implement batch worker
- [x] Implement `batchWorker()` replacing `worker()` — collects messages, flushes on ticker/size/close
- [x] Implement `flush(batch []alertMsg)` — builds `[]csAlert` array, single POST, 401 retry
- [x] Flush remaining batch on channel close (graceful drain)
- [x] Immediate mode: when `batchInterval == 0`, use `batchSize = 1` (flush every message)
- [x] Per-alert metrics: increment `CrowdSecAlerts` once per alert in batch, not per POST
- [x] Unit test: 5 alerts within interval → 1 POST with 5-element array
- [x] Unit test: batch size exceeded → immediate flush before timer
- [x] Unit test: Close() flushes remaining batch
- [x] Unit test: immediate mode (interval=0) sends each alert individually
- [x] Unit test: 401 retry works for batch POST

**Files**: `internal/alert/crowdsec.go`, `internal/alert/crowdsec_test.go`

### Task 3.2: Remove old worker, wire batch worker
- [x] Replace `go a.worker()` with `go a.batchWorker()` in constructor
- [x] Remove old `worker()` and `push()` methods
- [x] Verify all existing tests pass (alert format, auth, drain, overflow)

**Files**: `internal/alert/crowdsec.go`

## Phase 4: Decision Cache

### Task 4.1: Implement DecisionCache interface and local implementation
- [x] Define `DecisionCache` interface: `IsBanned(ip string) bool`, `MarkBanned(ip string, duration time.Duration)`
- [x] Implement `localDecisionCache` with `bans map[string]time.Time`, `mu`, `nowFunc`
- [x] `IsBanned`: return true if ip exists and expiry is future; delete expired on lookup
- [x] `MarkBanned`: set `bans[ip] = now + duration`; permanent ban (duration 0) uses far-future sentinel
- [x] Implement `noopDecisionCache` (IsBanned always false, MarkBanned no-op)
- [x] Implement `cleanup()` — sweep expired entries
- [x] Unit tests: mark and check, expiry, permanent ban, cleanup, noop

**Files**: `internal/alert/decision_cache.go`, `internal/alert/decision_cache_test.go`

### Task 4.2: Integrate decision cache into CrowdSecAlerter
- [x] Add `decisionCache DecisionCache` field
- [x] Initialize as `localDecisionCache` or `noopDecisionCache` based on config
- [x] Check `decisionCache.IsBanned(ip)` in `Alert()` — before dedup check
- [x] Increment `CrowdSecCached` metric on cache hit
- [x] Call `decisionCache.MarkBanned(ip, banDuration)` in `flush()` after successful POST
- [x] Add `banDurationRaw time.Duration` field (needed for MarkBanned, original duration not formatted string)
- [x] Piggyback cache cleanup on dedup cleanup goroutine
- [x] Integration test: alert IP, verify second alert is suppressed by cache
- [x] Integration test: cache expiry allows new alert

**Files**: `internal/alert/crowdsec.go`, `internal/alert/crowdsec_test.go`

## Phase 5: Documentation

### Task 5.1: Update README / docs
- [x] Document new env vars with defaults and examples
- [x] Add a section explaining the alert pipeline and filtering behavior
- [x] Example docker-compose snippet with recommended values

**Files**: `README.md` or relevant docs
