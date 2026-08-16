## MODIFIED Requirements

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

### Requirement: CrowdSec LAPI push
The worker SHALL POST alerts to `{RAN_CROWDSEC_URL}/v1/alerts` with a JWT token in the `Authorization: Bearer <token>` header, obtained via machine-login. On a 401 response, the worker SHALL attempt one inline re-login and retry the push. If the retry also fails, the alert SHALL be dropped with a warning log and failure metric.

#### Scenario: Successful push
- **WHEN** the LAPI is reachable and the token is valid
- **THEN** the alert is accepted and `ran_crowdsec_alerts_total{protocol,status="success"}` is incremented

#### Scenario: LAPI unreachable
- **WHEN** the LAPI returns an error or is unreachable
- **THEN** a warning is logged, `ran_crowdsec_alerts_total{protocol,status="failure"}` is incremented, and the worker continues

#### Scenario: Token expired (401 response)
- **WHEN** the LAPI returns 401 Unauthorized
- **THEN** the worker SHALL attempt one re-login and retry the push
- **AND** if the retry succeeds, `ran_crowdsec_alerts_total{protocol,status="success"}` is incremented
- **AND** if the retry fails, the alert is dropped with a warning log and failure metric

### Requirement: Self-contained decisions
Each alert SHALL include an embedded ban decision with the configured duration, `Ip` scope (capital I), and protocol-specific scenario name.

#### Scenario: SSH trap alert
- **WHEN** an SSH auth_attempt from 1.2.3.4 triggers an alert
- **THEN** the alert contains scenario `custom/ran-ssh-trap`, source scope `Ip`, source value `1.2.3.4`, and a ban decision with scope `Ip`, the configured duration, and origin `ran`

## ADDED Requirements

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
