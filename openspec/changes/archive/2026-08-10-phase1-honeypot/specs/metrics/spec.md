## ADDED Requirements

### Requirement: Prometheus metrics endpoint
The metrics server SHALL serve Prometheus metrics on `RAN_METRICS_ADDR` (default `:9550`) at `/metrics`.

#### Scenario: Scrape endpoint
- **WHEN** Alloy/Prometheus scrapes `GET /metrics`
- **THEN** all registered metrics are returned in Prometheus exposition format

### Requirement: Connection counter
`ran_connections_total{protocol}` SHALL be a counter incremented on each new connection. Protocol labels: `ssh`, `http`, `mysql`.

#### Scenario: SSH connection
- **WHEN** an SSH connection is accepted
- **THEN** `ran_connections_total{protocol="ssh"}` is incremented by 1

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
