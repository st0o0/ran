## MODIFIED Requirements

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
