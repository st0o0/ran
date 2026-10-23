## Purpose

CrowdSec integration for reporting honeypot intrusion attempts to the CrowdSec Local API, enabling community-driven IP reputation and automated banning.
## Requirements
### Requirement: Alerter interface
The system SHALL define an `Alerter` interface with an `Alert(ctx context.Context, ip string, protocol string, meta map[string]string)` method. A no-op implementation SHALL be used when CrowdSec is disabled. The `meta` parameter carries trap-specific key-value metadata (e.g. username, password, command). Callers MAY pass `nil` when no metadata is available.

#### Scenario: CrowdSec disabled
- **WHEN** `RAN_CROWDSEC=off`
- **THEN** the no-op alerter is used and no alerts are sent

#### Scenario: CrowdSec enabled
- **WHEN** `RAN_CROWDSEC=on`
- **THEN** the CrowdSec alerter is used and alerts are pushed to LAPI

#### Scenario: Alert with metadata
- **WHEN** a trap calls `Alert(ctx, "1.2.3.4", "ssh", map[string]string{"username": "root", "password": "admin"})`
- **THEN** the metadata is included in the CrowdSec event's meta array

#### Scenario: Alert without metadata
- **WHEN** a trap calls `Alert(ctx, "1.2.3.4", "memcached", nil)`
- **THEN** the alert is pushed with an event containing an empty meta array

### Requirement: Non-blocking alert delivery
Alerts SHALL be sent via a buffered channel (capacity 256) consumed by a single worker goroutine. If the channel is full, the alert SHALL be dropped, a warning logged, and `ran_crowdsec_alerts_dropped_total{protocol}` incremented. The `Alert()` method SHALL increment `ran_crowdsec_pipeline_total{stage="received"}` on every call, then increment the appropriate stage counter (`cached`, `deduplicated`, `queued`, or `dropped`) based on the outcome.

#### Scenario: Normal alert flow
- **WHEN** a trap detects an auth_attempt
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` is incremented
- **AND** the alert is sent to the channel
- **AND** `ran_crowdsec_pipeline_total{stage="queued"}` is incremented

#### Scenario: Channel full
- **WHEN** 256 alerts are queued and another arrives
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` and `{stage="dropped"}` are incremented
- **AND** `ran_crowdsec_alerts_dropped_total{protocol}` is incremented
- **AND** a warning is logged with `source_ip` (not `ip`)

#### Scenario: IP already banned
- **WHEN** the decision cache reports the IP is banned
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` and `{stage="cached"}` are incremented
- **AND** a debug log with `source_ip` field is emitted

#### Scenario: Duplicate suppressed
- **WHEN** the dedup filter suppresses the alert
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` and `{stage="deduplicated"}` are incremented

### Requirement: CrowdSec LAPI push
The worker SHALL POST alerts to `{RAN_CROWDSEC_URL}/v1/alerts` with a JWT token in the `Authorization: Bearer <token>` header, obtained via machine-login. On success, `ran_crowdsec_pipeline_total{stage="sent"}` SHALL be incremented. On failure, `ran_crowdsec_pipeline_total{stage="failed"}` SHALL be incremented. On a 401 response, the worker SHALL attempt one inline re-login and retry the push.

#### Scenario: Successful push
- **WHEN** the LAPI is reachable and the token is valid
- **THEN** the alert is accepted and `ran_crowdsec_pipeline_total{protocol,stage="sent"}` is incremented

#### Scenario: LAPI unreachable
- **WHEN** the LAPI returns an error or is unreachable
- **THEN** a warning is logged, `ran_crowdsec_pipeline_total{protocol,stage="failed"}` is incremented

#### Scenario: Token expired (401 response)
- **WHEN** the LAPI returns 401 Unauthorized
- **THEN** the worker SHALL attempt one re-login and retry the push
- **AND** if the retry fails, `ran_crowdsec_pipeline_total{protocol,stage="failed"}` is incremented

### Requirement: Self-contained decisions
Each alert SHALL include an embedded ban decision with the configured duration, `Ip` scope (capital I), and protocol-specific scenario name.

#### Scenario: SSH trap alert
- **WHEN** an SSH auth_attempt from 1.2.3.4 triggers an alert
- **THEN** the alert contains scenario `custom/ran-ssh-trap`, source scope `Ip`, source value `1.2.3.4`, and a ban decision with scope `Ip`, the configured duration, and origin `ran`

### Requirement: Per-protocol scenario names
Alerts SHALL use scenario names: `custom/ran-ssh-trap`, `custom/ran-http-trap`, `custom/ran-mysql-trap`.

#### Scenario: MySQL trap
- **WHEN** a MySQL auth_attempt triggers an alert
- **THEN** the scenario is `custom/ran-mysql-trap`

### Requirement: Configurable ban duration
The ban duration SHALL be set via `RAN_CROWDSEC_BAN_DURATION` (default `4h`). A value of `0` SHALL mean permanent ban.

#### Scenario: Default ban
- **WHEN** `RAN_CROWDSEC_BAN_DURATION` is not set
- **THEN** the decision duration is `4h`

#### Scenario: Permanent ban
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=0`
- **THEN** the decision duration is `0` (permanent)

### Requirement: Machine-login authentication
The alerter SHALL authenticate to CrowdSec LAPI via `POST /v1/watchers/login` with `machine_id` and `password` fields. The LAPI returns a JSON response with `token` (JWT string) and `expire` (RFC3339 timestamp). The alerter SHALL store both and use the token for all subsequent API calls.

#### Scenario: Successful login
- **WHEN** `POST /v1/watchers/login` is called with valid credentials
- **THEN** the alerter stores the returned JWT token and its expiry time

#### Scenario: Invalid credentials
- **WHEN** `POST /v1/watchers/login` returns a non-2xx status
- **THEN** the login SHALL return an error

#### Scenario: LAPI unreachable during login
- **WHEN** `POST /v1/watchers/login` fails due to network error
- **THEN** the login SHALL return an error

### Requirement: Eager login on startup
`NewCrowdSec()` SHALL perform a synchronous login during construction. If the login fails, `NewCrowdSec()` SHALL return an error, preventing ran from starting with invalid CrowdSec credentials.

#### Scenario: Startup with valid credentials
- **WHEN** `NewCrowdSec()` is called and login succeeds
- **THEN** a `CrowdSecAlerter` is returned with a valid token

#### Scenario: Startup with invalid credentials
- **WHEN** `NewCrowdSec()` is called and login fails
- **THEN** an error is returned and no alerter is created

### Requirement: Proactive token refresh
The alerter SHALL run a background goroutine that refreshes the JWT token at 80% of its lifetime. On refresh failure, the goroutine SHALL retry with exponential backoff (starting at 10s, doubling, capped at 60s) until either the refresh succeeds or the alerter is closed.

#### Scenario: Normal refresh
- **WHEN** the token lifetime is 1 hour
- **THEN** the refresh goroutine attempts re-login at 48 minutes (80%)

#### Scenario: Refresh failure with retry
- **WHEN** the LAPI is temporarily unreachable during refresh
- **THEN** the goroutine retries after 10s, then 20s, then 40s, then 60s, capped at 60s

#### Scenario: Refresh failure logging
- **WHEN** a token refresh attempt fails
- **THEN** a warning-level log is emitted with the error

#### Scenario: Shutdown during refresh
- **WHEN** `Close()` is called while the refresh goroutine is waiting
- **THEN** the refresh goroutine exits promptly

### Requirement: Graceful shutdown
On shutdown, the alerter SHALL stop the refresh goroutine and drain remaining alerts from the channel (up to 5 seconds) before exiting.

#### Scenario: Shutdown stops refresh and drains alerts
- **WHEN** `Close()` is called with 3 alerts in the channel
- **THEN** the refresh goroutine stops and the worker attempts to push all 3 alerts before exiting

### Requirement: Events field in LAPI payload
Each alert pushed to CrowdSec LAPI SHALL include an `events` field containing a JSON array with exactly one event object. The event SHALL have a `timestamp` (RFC3339, matching the alert's `start_at`) and a `meta` array of `{"key": "...", "value": "..."}` objects built from the trap-provided metadata map. If no metadata is provided, the `meta` array SHALL be empty. The `events` array SHALL never be `null` or absent.

#### Scenario: Alert with metadata produces populated event
- **WHEN** `push()` builds an alert with metadata `{"username": "root", "password": "admin"}`
- **THEN** the JSON payload includes `"events": [{"timestamp": "...", "meta": [{"key": "password", "value": "admin"}, {"key": "username", "value": "root"}]}]`
- **AND** meta entries are sorted alphabetically by key

#### Scenario: Alert without metadata produces empty-meta event
- **WHEN** `push()` builds an alert with `nil` metadata
- **THEN** the JSON payload includes `"events": [{"timestamp": "...", "meta": []}]`

#### Scenario: Events array is never null
- **WHEN** any alert is marshalled to JSON
- **THEN** the `events` field is a JSON array (`[]` or `[{...}]`), never `null` or absent

### Requirement: Source and decision scope casing
The `source.scope` and `decisions[].scope` fields SHALL use the value `"Ip"` (capital I, lowercase p) to match CrowdSec's canonical scope constant.

#### Scenario: Source scope casing
- **WHEN** an alert is built for any IP
- **THEN** `source.scope` is `"Ip"`

#### Scenario: Decision scope casing
- **WHEN** an alert includes a ban decision
- **THEN** `decisions[].scope` is `"Ip"`

### Requirement: Consistent source_ip field in CrowdSec logs
All CrowdSec log events SHALL use the field name `source_ip` instead of `ip`.

#### Scenario: Alert skipped log
- **WHEN** an alert is skipped because the IP is cached
- **THEN** the log event uses `"source_ip": "1.2.3.4"`, not `"ip": "1.2.3.4"`

#### Scenario: Alert pushed log
- **WHEN** an alert is successfully pushed
- **THEN** the log event uses `"source_ip": "1.2.3.4"`

### Requirement: Pipeline stage logging
CrowdSec log events for alert pipeline stages SHALL include a `stage` field matching the pipeline metric stage values.

#### Scenario: Cached alert log
- **WHEN** an alert is skipped because the IP is in the decision cache
- **THEN** the log includes `"stage": "cached"`

#### Scenario: Sent alert log
- **WHEN** an alert is successfully pushed to LAPI
- **THEN** the log includes `"stage": "sent"`

### Requirement: Alert IP validation
`Alert()` SHALL parse the IP with `netip.ParseAddr`, reject zoned addresses, unmap IPv4-mapped IPv6 addresses, and reject every address inside an explicit denylist of non-global prefixes: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 3fff::/20, 5f00::/16, fc00::/7, fe80::/10, ff00::/8 and ::/96. Rejected addresses SHALL be dropped before cache and dedup, counted as pipeline stage `invalid`.

#### Scenario: Non-IP string
- **WHEN** `Alert(ctx, "not-an-ip", "http", nil)` is called
- **THEN** nothing is queued and stage `invalid` is incremented

#### Scenario: Private or loopback address
- **WHEN** `Alert()` is called with `10.0.0.5`, `100.64.0.1`, `127.0.0.1`, `169.254.1.1`, `0.0.0.0`, `203.0.113.9`, `224.0.0.1`, `::1` or `2001:db8::1`
- **THEN** nothing is queued and stage `invalid` is incremented

#### Scenario: IPv4-mapped IPv6
- **WHEN** `Alert()` is called with `::ffff:8.8.8.8`
- **THEN** the alert is queued with the unmapped IPv4 form as source value

### Requirement: Bounded dedup and decision cache
The dedup filter and the local decision cache SHALL each hold at most `RAN_CROWDSEC_MAX_TRACKED` entries (default 100000). Both SHALL be FIFO structures: on overflow expired dedup entries SHALL be dropped from the front, then the oldest entry of either structure evicted, each in O(1) amortized time without scanning the whole map under the lock. The decision cache SHALL sweep expired entries only from its cleanup loop.

#### Scenario: Map at capacity
- **WHEN** more unique IPs arrive than the cap
- **THEN** map size never exceeds the cap

#### Scenario: Flood of unique keys
- **WHEN** 200000 unique keys are inserted into a full dedup map or decision cache
- **THEN** the inserts complete well under 2 seconds and the size stays at the cap

### Requirement: Dedup slot recorded only on enqueue
The dedup slot SHALL be consumed only when the alert is successfully enqueued. If the channel is full and the alert is dropped, the slot SHALL be released, and only if the stored slot is still the one the alert took. `Close()` SHALL be idempotent and `Alert()` SHALL NOT send on a closed channel, including when called concurrently with `Close()`.

#### Scenario: Dropped alert is retried
- **WHEN** an alert is dropped because the channel is full and the same IP alerts again after space is available
- **THEN** the second alert is not suppressed by dedup

### Requirement: No password in CrowdSec meta
The alerter SHALL remove the `password` key from event meta before building the LAPI payload.

#### Scenario: Credential alert
- **WHEN** a trap calls `Alert()` with meta containing `username` and `password`
- **THEN** the LAPI event meta contains `username` and no `password`

### Requirement: Alerts after Close are counted
`Alert()` called after `Close()` SHALL NOT queue the alert and SHALL increment the pipeline stage `closed` (and log at debug) instead of returning silently.

#### Scenario: Alert after Close
- **WHEN** `Alert()` is called with a valid public IP after `Close()`
- **THEN** nothing is queued and stage `closed` is incremented

### Requirement: Decision cache keeps the longest ban
`MarkBanned` on an IP that is already cached SHALL keep the later of the existing and the new expiry, so a shorter ban never shortens a longer or permanent one.

#### Scenario: Shorter re-mark
- **WHEN** an IP is marked banned for 4 hours and then marked again for 1 minute
- **THEN** the IP stays cached as banned for the 4 hour window

### Requirement: Eviction trade-off is documented
The dedup filter and decision cache SHALL document in code that a flood of unique sources can evict an entry still inside its window, so a repeat alert may pass, and that the LAPI stays authoritative.

#### Scenario: Flood of unique sources
- **WHEN** more unique sources arrive than the tracked-entry cap
- **THEN** the oldest entry is evicted even if it is still inside its window, a repeat alert for it may pass, and the comments in dedup.go and decision_cache.go state this trade-off

