## MODIFIED Requirements

### Requirement: Session logging
Each Elasticsearch connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`elasticsearch`), and action (`connect`, `command`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext` and `DestPortFromContext(r.Context())`, not from the config value.

#### Scenario: Single-port destPort
- **WHEN** the Elasticsearch trap listens on `:9200` and a connection arrives
- **THEN** the session's dest_port is 9200, derived from `r.Context()`

#### Scenario: Multi-port destPort
- **WHEN** the Elasticsearch trap listens on `[":9200", ":9300"]` and a connection arrives on port 9300
- **THEN** the session's dest_port is 9300, derived from `r.Context()`
