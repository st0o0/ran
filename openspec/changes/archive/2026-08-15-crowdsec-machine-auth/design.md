## Context

ran pushes honeypot alerts to CrowdSec LAPI via `POST /v1/alerts` using a bouncer API key (`X-Api-Key` header). This is architecturally wrong — `POST /v1/alerts` is a machine-authenticated endpoint. Bouncer keys are designed for `GET /v1/decisions`. The current approach works because CrowdSec LAPI accepts bouncer keys on the alerts endpoint, but it violates the intended auth model.

CrowdSec machine auth flow:
1. Register machine out-of-band: `cscli machines add -m <id> -p <password>`
2. Login: `POST /v1/watchers/login` with `{machine_id, password}` → `{token, expire}`
3. Use JWT: `Authorization: Bearer <token>` on subsequent API calls
4. Refresh before expiry

Current code: `CrowdSecAlerter` struct holds `apiKey string`, `NewCrowdSec()` takes `apiKey` param, `push()` sets `X-Api-Key` header. Single worker goroutine drains a buffered channel.

## Goals / Non-Goals

**Goals:**
- Switch authentication from bouncer API-key to machine-login JWT
- Proactive token refresh so alerts are never delayed by login latency
- Fail-fast on startup if credentials are wrong
- Resilient to temporary LAPI outages during token refresh

**Non-Goals:**
- Auto-registration of machines (`POST /v1/watchers`) — remains out-of-band via `cscli`
- Retry logic for failed alert pushes (existing behavior: log + metric, move on)
- TLS client certificate auth (CrowdSec supports it, but machine-login is sufficient)

## Decisions

### Token lifecycle: proactive background refresh

The `CrowdSecAlerter` runs a `refreshLoop` goroutine that refreshes the JWT at 80% of its lifetime. On refresh failure, it retries with exponential backoff (10s, 20s, 40s, capped at 60s). The old token remains valid during retries (20% remaining lifetime).

As a safety net, `push()` handles 401 responses by attempting one inline login + retry. This covers edge cases: clock skew, server-side token revocation, or refresh goroutine falling behind.

**Alternative considered**: Lazy login in `getToken()` — simpler, but adds login latency to the first alert after expiry. Since ran has a single sequential worker, this would block all queued alerts during login. Proactive refresh avoids this.

**Alternative considered**: Retry-on-401 only — reactive, no timing logic needed. But every token expiry costs one failed request + retry. Proactive is cleaner for the normal case.

### Eager login on construction

`NewCrowdSec()` calls `login()` synchronously and returns an error if it fails. This provides fail-fast behavior: wrong credentials or unreachable LAPI are caught at startup, not silently at the first alert minutes later.

**Signature change**: `NewCrowdSec(...) *CrowdSecAlerter` → `NewCrowdSec(...) (*CrowdSecAlerter, error)`

### Concurrency model

Two goroutines access the token: `refreshLoop` (writes) and `worker` via `push` (reads). A `sync.RWMutex` protects the token and expiry fields. `push` takes RLock, `refreshLoop` and the 401-retry path take full Lock.

The 401-retry in `push` also acquires the write lock. To avoid redundant logins when `refreshLoop` just refreshed, `push` re-checks the token after acquiring the lock (double-check pattern).

### Shutdown

`Close()` closes two channels: `ch` (alert channel, existing) and `stopCh` (new, for refreshLoop). It waits for both goroutines via a `sync.WaitGroup` with a 5-second timeout (existing behavior extended to cover refreshLoop).

## Risks / Trade-offs

- **LAPI down at startup** → ran fails to start. This is intentional (fail-fast). If ran needs to start without LAPI, the user sets `RAN_CROWDSEC=off`. Mitigation: clear error message indicating LAPI login failed.
- **Token refresh fails repeatedly** → old token expires, push gets 401, inline retry attempts login. If that also fails, alerts are dropped (same as current behavior when LAPI is down). Mitigation: warn-level logging on every refresh failure.
- **Breaking change** → existing deployments using `RAN_CROWDSEC_API_KEY` will fail on upgrade. Mitigation: clear error message suggesting the new env vars. No migration path needed — users must register a machine and update their config.

## Open Questions

_None — all decisions resolved during exploration._
