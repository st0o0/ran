## MODIFIED Requirements

### Requirement: Entrypoint with signal handling
The main function SHALL parse config, start all enabled traps as goroutines, and block until SIGTERM or SIGINT is received. On signal, all traps SHALL be stopped via context cancellation and `Stop`, which closes active sessions, bounded by the shutdown timeout.

#### Scenario: Graceful shutdown
- **WHEN** SIGTERM is sent to the process
- **THEN** all trap listeners stop accepting new connections, active sessions are closed immediately, traps stop within the shutdown timeout, and the process exits 0

#### Scenario: No traps enabled
- **WHEN** the binary is run without any `RAN_*` env vars (no traps enabled)
- **THEN** config validation fails and the process exits with code 1 and a descriptive error
