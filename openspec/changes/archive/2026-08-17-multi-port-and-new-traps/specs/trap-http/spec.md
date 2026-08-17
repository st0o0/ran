## MODIFIED Requirements

### Requirement: Session logging
Each HTTP connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`http`), and action (`connect`, `auth_attempt`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext`, not from the config value.

#### Scenario: Single-port destPort
- **WHEN** the HTTP trap listens on `:8081` and a connection arrives
- **THEN** the session's dest_port is 8081, derived from `ConnContext`

#### Scenario: Multi-port destPort
- **WHEN** the HTTP trap listens on `[":8081", ":8443"]` and a connection arrives on port 8443
- **THEN** the session's dest_port is 8443, derived from `ConnContext`
