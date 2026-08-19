# CrowdSec Alert Optimization

## Problem

Ran sends a separate HTTP POST to CrowdSec LAPI for every single honeypot connection — no deduplication, no batching, no awareness of existing bans. Under attack, this creates a vicious cycle:

- A single IP hitting the SMTP trap generates ~15 alerts in 13 seconds
- Already-banned IPs (VNC scanners like 45.87.251.43, 37.58.131.227) trigger new alerts every 10-20 seconds
- This floods the CrowdSec database, degrading LAPI performance
- Degraded LAPI means bans aren't enforced, so IPs keep coming back

The alert channel's 256-slot buffer is the only throttle, silently dropping alerts on overflow.

## Solution

Three incremental optimizations in the `CrowdSecAlerter`, each independently valuable:

### 1. Alert Deduplication / Cooldown (highest impact)

Suppress repeated alerts for the same IP+Scenario combination within a configurable time window.

- Key: `"{ip}|{scenario}"` → last-alert timestamp
- First alert always goes through immediately
- Subsequent alerts within the window are skipped (logged at debug level)
- Periodic cleanup of expired entries to prevent unbounded map growth
- Expected reduction: **90%+ of alert volume**

```
RAN_CROWDSEC_DEDUP_WINDOW=5m    (default: 5m, 0 to disable)
```

### 2. Alert Batching

Collect alerts over a time window and flush them as a single `POST /v1/alerts` containing multiple alert objects. CrowdSec LAPI natively supports arrays of alerts.

- Replaces the current 1-alert-per-POST worker loop with a ticker-based batch flush
- Flush triggers: timer expiry OR buffer reaching a max size OR `Close()` called
- Mixed IPs and scenarios within a single batch are fine

```
RAN_CROWDSEC_BATCH_INTERVAL=10s (default: 10s, 0 to disable / send immediately)
RAN_CROWDSEC_BATCH_SIZE=50      (default: 50, max alerts per POST)
```

### 3. Decision Cache (local, self-informed)

After successfully pushing an alert with a ban decision, cache the ban locally. Skip future alerts for IPs that are still within their ban duration.

- Passive / Option A: Ran remembers its own bans (no extra LAPI calls)
- TTL-based: entry expires when the ban duration elapses
- Sits behind a `DecisionCache` interface so active LAPI polling (Option B, requires bouncer API key) can be added later without changing consumers

```
RAN_CROWDSEC_DECISION_CACHE=on  (default: on, off to disable)
```

Option B (active polling via `GET /v1/decisions` with a bouncer API key) is architecturally prepared but **not part of this change**. It would require a second credential (`RAN_CROWDSEC_BOUNCER_KEY`) and a separate auth path.

## Alert Pipeline After Optimization

```
alerter.Alert(ip, protocol, meta)
         │
         ▼
  ┌──────────────┐
  │ Decision     │── IP still banned? ──▶ skip (debug log)
  │ Cache check  │
  └──────┬───────┘
         │ not banned
         ▼
  ┌──────────────┐
  │ Dedup check  │── reported within window? ──▶ skip (debug log)
  │ (IP+Scenario)│
  └──────┬───────┘
         │ new or cooldown expired
         ▼
  ┌──────────────┐
  │ Batch queue  │── collect ──▶ flush on timer/size/close
  └──────────────┘                      │
                                        ▼
                                POST /v1/alerts (N alerts)
                                        │
                                        ▼
                                Update Decision Cache
                                (mark IPs as banned)
```

## What's NOT In Scope

- **Max Alerts per IP (hard cap)**: Dedup makes this redundant. If needed later, it's a simple counter on top of dedup.
- **Connection-Drop for banned IPs**: Requires Decision Cache + changes to the Listener/Trap layer (30+ files). More importantly, there's a design tension between dropping connections (efficient) vs. tarpitting (wastes attacker resources). This deserves its own proposal.
- **Active decision polling (Option B)**: Architecturally prepared via interface, but the bouncer API key requirement and second auth path make it a separate change.

## Affected Code

| File | Change |
|------|--------|
| `internal/alert/crowdsec.go` | Dedup map, batch worker, decision cache, new config fields |
| `internal/alert/crowdsec_test.go` | Tests for dedup, batching, cache behavior |
| `internal/config/config.go` | New env vars (5 new fields) |
| `internal/alert/alerter.go` | No change — `Alerter` interface stays the same |
| `internal/trap/*.go` | **No changes** — all filtering is internal to the alerter |

The `Alerter` interface (`Alert(ctx, ip, protocol, meta)`) does not change. All 30+ trap files remain untouched.

## Configuration Summary

| Env Var | Default | Description |
|---------|---------|-------------|
| `RAN_CROWDSEC_DEDUP_WINDOW` | `5m` | Cooldown per IP+Scenario (0 = disabled) |
| `RAN_CROWDSEC_BATCH_INTERVAL` | `10s` | Batch flush interval (0 = immediate, no batching) |
| `RAN_CROWDSEC_BATCH_SIZE` | `50` | Max alerts per batch POST |
| `RAN_CROWDSEC_DECISION_CACHE` | `on` | Cache own ban decisions locally |
