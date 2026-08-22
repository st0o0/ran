## Purpose

Connection outcome tracking to distinguish normal disconnects from timeouts and errors, enabling outcome-based metrics and log queries.

## Requirements

### Requirement: Outcome field on disconnect
`LogDisconnect()` SHALL include an `outcome` field with one of these bounded values: `completed`, `timeout`, `error`.

#### Scenario: Normal disconnect
- **WHEN** a client disconnects without errors
- **THEN** the disconnect log has `"outcome": "completed"`

#### Scenario: Deadline exceeded
- **WHEN** a session's read/write deadline expires
- **THEN** the disconnect log has `"outcome": "timeout"`

#### Scenario: Connection error
- **WHEN** a read/write or handshake error occurs
- **THEN** the disconnect log has `"outcome": "error"`

### Requirement: Outcome settable on Session
The `Session` struct SHALL have a method to set the outcome. The default outcome SHALL be `"completed"`. Code paths that detect timeouts or errors SHALL set the appropriate outcome before `LogDisconnect()` is called.

#### Scenario: Timeout detection
- **WHEN** a `net.Error` with `Timeout() == true` is returned from a read/write
- **THEN** the trap handler calls `sess.SetOutcome("timeout")`
- **AND** the deferred `LogDisconnect()` includes `"outcome": "timeout"`

#### Scenario: Default outcome
- **WHEN** no explicit outcome is set
- **THEN** `LogDisconnect()` uses `"outcome": "completed"`

### Requirement: Outcome label on connections metric
`ran_connections_total` SHALL include an `outcome` label with values `completed`, `timeout`, `error`, `rejected`.

#### Scenario: Completed SSH connection
- **WHEN** an SSH session ends normally
- **THEN** `ran_connections_total{protocol="ssh", outcome="completed"}` is incremented

#### Scenario: Timed-out connection
- **WHEN** a session times out
- **THEN** `ran_connections_total{protocol="ssh", outcome="timeout"}` is incremented

#### Scenario: Rejected connection
- **WHEN** a connection is rejected by the rate limiter
- **THEN** `ran_connections_total{protocol="ssh", outcome="rejected"}` is incremented

### Requirement: Outcome passed to RecordEnd
`RecordEnd()` SHALL accept an outcome string parameter and use it as the `outcome` label value when observing the session duration histogram and decrementing active sessions.

#### Scenario: RecordEnd with timeout
- **WHEN** `RecordEnd("timeout")` is called
- **THEN** the session duration is observed and `ran_connections_total{outcome="timeout"}` reflects the outcome
