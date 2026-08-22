## MODIFIED Requirements

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
The worker SHALL POST alerts to `{RAN_CROWDSEC_URL}/v1/alerts` with a JWT token. On success, `ran_crowdsec_pipeline_total{stage="sent"}` SHALL be incremented. On failure, `ran_crowdsec_pipeline_total{stage="failed"}` SHALL be incremented.

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

## ADDED Requirements

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
