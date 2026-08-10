## Purpose

Process lifecycle management including entrypoint, signal handling, graceful shutdown, subcommands, connection limiting, and session tracking.

## Requirements

### Requirement: Entrypoint with signal handling
The main function SHALL parse config, start all enabled traps as goroutines, and block until SIGTERM or SIGINT is received. On signal, all traps SHALL be stopped gracefully via context cancellation.

#### Scenario: Graceful shutdown
- **WHEN** SIGTERM is sent to the process
- **THEN** all trap listeners stop accepting new connections, active sessions drain (up to a timeout), and the process exits 0

#### Scenario: No traps enabled
- **WHEN** the binary is run without any `RAN_*` env vars (no traps enabled)
- **THEN** config validation fails and the process exits with code 1 and a descriptive error

### Requirement: Healthcheck subcommand
`ran healthcheck` SHALL exit 0 if the metrics server is reachable (TCP dial to metrics addr), exit 1 otherwise.

#### Scenario: Healthy process
- **WHEN** `ran healthcheck` is run while the metrics server is listening
- **THEN** it exits with code 0

#### Scenario: Unhealthy process
- **WHEN** `ran healthcheck` is run but the metrics server is not reachable
- **THEN** it exits with code 1

### Requirement: Version subcommand
`ran version` SHALL print the version string (injected via ldflags) and exit 0.

#### Scenario: Version output
- **WHEN** `ran version` is run
- **THEN** the build version is printed to stdout

### Requirement: Connection limiter
A shared connection limiter SHALL enforce `RAN_MAX_SESSIONS` (global) and `RAN_MAX_PER_IP` (per source IP). Excess connections SHALL be accepted, logged at warn level, and immediately closed.

#### Scenario: Global limit reached
- **WHEN** 500 sessions are active and a new connection arrives
- **THEN** the connection is accepted, a warning is logged, and the connection is closed

#### Scenario: Per-IP limit reached
- **WHEN** 10 sessions from the same IP are active and another arrives from that IP
- **THEN** the connection is accepted, a warning is logged, and the connection is closed

### Requirement: Session UUID
Every connection SHALL be assigned a UUID v4 as `session_id`, included in all log entries for that connection.

#### Scenario: Correlated logs
- **WHEN** an SSH connection produces connect, auth_attempt, and disconnect events
- **THEN** all three log entries share the same `session_id`
