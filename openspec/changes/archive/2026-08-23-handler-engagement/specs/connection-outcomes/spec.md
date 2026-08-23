## MODIFIED Requirements

### Requirement: Outcome field on disconnect
`LogDisconnect()` SHALL include an `outcome` field with one of these bounded values: `completed`, `timeout`, `error`, `probe`.

#### Scenario: Normal disconnect
- **WHEN** a client disconnects without errors
- **THEN** the disconnect log has `"outcome": "completed"`

#### Scenario: Deadline exceeded
- **WHEN** a session's read/write deadline expires
- **THEN** the disconnect log has `"outcome": "timeout"`

#### Scenario: Connection error
- **WHEN** a read/write or handshake error occurs
- **THEN** the disconnect log has `"outcome": "error"`

#### Scenario: Scanner probe
- **WHEN** a connection sends data that does not match the expected protocol (e.g., non-TDS data on MSSQL port, non-SMB data on SMB port)
- **THEN** the disconnect log has `"outcome": "probe"`

### Requirement: Outcome label on connections metric
`ran_connections_total` SHALL include an `outcome` label with values `completed`, `timeout`, `error`, `rejected`, `probe`.

#### Scenario: Completed SSH connection
- **WHEN** an SSH session ends normally
- **THEN** `ran_connections_total{protocol="ssh", outcome="completed"}` is incremented

#### Scenario: Timed-out connection
- **WHEN** a session times out
- **THEN** `ran_connections_total{protocol="ssh", outcome="timeout"}` is incremented

#### Scenario: Rejected connection
- **WHEN** a connection is rejected by the rate limiter
- **THEN** `ran_connections_total{protocol="ssh", outcome="rejected"}` is incremented

#### Scenario: Probe connection
- **WHEN** a scanner connects to the MSSQL port and sends non-TDS data
- **THEN** `ran_connections_total{protocol="mssql", outcome="probe"}` is incremented
