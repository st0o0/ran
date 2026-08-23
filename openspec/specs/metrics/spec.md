## Purpose

Prometheus metrics instrumentation for monitoring honeypot connections, credential captures, active sessions, and session durations.

## Requirements

### Requirement: Prometheus metrics endpoint
The metrics server SHALL serve Prometheus metrics on `RAN_METRICS_ADDR` (default `:9550`) at `/metrics`.

#### Scenario: Scrape endpoint
- **WHEN** Alloy/Prometheus scrapes `GET /metrics`
- **THEN** all registered metrics are returned in Prometheus exposition format

### Requirement: Connection counter
`ran_connections_total{protocol, outcome}` SHALL be a counter incremented on each connection with the session's outcome. Outcome labels: `completed`, `timeout`, `error`, `rejected`, `probe`.

#### Scenario: Completed SSH connection
- **WHEN** an SSH connection completes normally
- **THEN** `ran_connections_total{protocol="ssh", outcome="completed"}` is incremented

#### Scenario: Timed-out connection
- **WHEN** a session exceeds its deadline
- **THEN** `ran_connections_total{protocol="ssh", outcome="timeout"}` is incremented

#### Scenario: Rejected connection
- **WHEN** a connection is rejected by the rate limiter
- **THEN** `ran_connections_total{protocol="ssh", outcome="rejected"}` is incremented

#### Scenario: Probe connection
- **WHEN** a scanner connects to the MSSQL port and sends non-TDS data
- **THEN** `ran_connections_total{protocol="mssql", outcome="probe"}` is incremented

### Requirement: Credential counter
`ran_credentials_captured_total{protocol}` SHALL be a counter incremented when credentials are captured from an auth attempt.

#### Scenario: HTTP credential capture
- **WHEN** credentials are extracted from an HTTP POST
- **THEN** `ran_credentials_captured_total{protocol="http"}` is incremented by 1

### Requirement: Active sessions gauge
`ran_active_sessions{protocol}` SHALL be a gauge tracking currently active sessions.

#### Scenario: Session lifecycle
- **WHEN** a session starts
- **THEN** the gauge increments; when the session ends, it decrements

### Requirement: Session duration histogram
`ran_session_duration_seconds{protocol}` SHALL be a histogram observing session durations.

#### Scenario: Short session
- **WHEN** a 2-second SSH session ends
- **THEN** `2.0` is observed in the histogram

### Requirement: Go and Process collectors
The custom Prometheus registry SHALL register `collectors.NewGoCollector()` and `collectors.NewProcessCollector()`, exposing standard `go_*` and `process_*` metrics including `process_start_time_seconds`.

#### Scenario: Process start time available
- **WHEN** Prometheus scrapes `/metrics`
- **THEN** `process_start_time_seconds` is present and reflects the process start time

#### Scenario: Go runtime metrics available
- **WHEN** Prometheus scrapes `/metrics`
- **THEN** `go_goroutines`, `go_memstats_alloc_bytes`, and other `go_*` metrics are present

### Requirement: Build info metric
`ran_build_info` SHALL be a gauge with constant value `1` and labels `version` and `goversion`.

#### Scenario: Version visible
- **WHEN** Prometheus scrapes `/metrics`
- **THEN** `ran_build_info{version="0.3.5", goversion="go1.24.4"}` has value `1`

### Requirement: CrowdSec dropped alerts counter
`ran_crowdsec_alerts_dropped_total{protocol}` SHALL be a counter incremented when an alert is dropped because the channel is full.

#### Scenario: Channel full
- **WHEN** the alert channel (capacity 256) is full and a new alert arrives
- **THEN** `ran_crowdsec_alerts_dropped_total{protocol="sip"}` is incremented

### Requirement: CrowdSec pipeline funnel metric
`ran_crowdsec_pipeline_total{protocol, stage}` SHALL be a counter tracking each stage of the alert pipeline. Stage values: `received`, `cached`, `deduplicated`, `queued`, `sent`, `failed`, `dropped`.

#### Scenario: Full pipeline success
- **WHEN** an alert is received, passes cache and dedup checks, is queued, and pushed successfully
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}`, `{stage="queued"}`, and `{stage="sent"}` are each incremented

#### Scenario: Alert cached
- **WHEN** an alert is received for an IP already in the decision cache
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` and `{stage="cached"}` are incremented

#### Scenario: Alert deduplicated
- **WHEN** an alert is received for an IP+scenario seen within the dedup window
- **THEN** `ran_crowdsec_pipeline_total{stage="received"}` and `{stage="deduplicated"}` are incremented

#### Scenario: Funnel arithmetic
- **WHEN** querying delivery rate
- **THEN** `rate(ran_crowdsec_pipeline_total{stage="sent"}[5m]) / rate(ran_crowdsec_pipeline_total{stage="received"}[5m])` gives the delivery ratio
