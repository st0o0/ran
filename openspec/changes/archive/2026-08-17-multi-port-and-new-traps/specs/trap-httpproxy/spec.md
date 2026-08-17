## MODIFIED Requirements

### Requirement: Session logging
Each HTTP proxy connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`httpproxy`), and action (`connect`, `auth_attempt`, `command`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext` and `DestPortFromContext(r.Context())`, not from the config value.

#### Scenario: Single-port destPort
- **WHEN** the HTTPProxy trap listens on `:8080` and a connection arrives
- **THEN** the session's dest_port is 8080, derived from `r.Context()`

#### Scenario: Multi-port destPort
- **WHEN** the HTTPProxy trap listens on `[":8080", ":3128"]` and a connection arrives on port 3128
- **THEN** the session's dest_port is 3128, derived from `r.Context()`
