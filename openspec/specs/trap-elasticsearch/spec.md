## Purpose

Elasticsearch honeypot trap that simulates an Elasticsearch HTTP API to capture unauthorized access and reconnaissance attempts.

## Requirements

### Requirement: Elasticsearch HTTP API trap
The Elasticsearch trap SHALL listen on TCP as an HTTP server, respond to common Elasticsearch API endpoints with fake cluster information, and log all requests.

#### Scenario: Root endpoint
- **WHEN** a client sends `GET /`
- **THEN** the trap SHALL respond with a JSON body containing fake cluster name, version, and tagline, and log the request

#### Scenario: Search/index request
- **WHEN** a client sends `GET /_search` or `PUT /index/_doc/1`
- **THEN** the trap SHALL log the request method, path, and body, and respond with a plausible JSON error

#### Scenario: Cluster health
- **WHEN** a client sends `GET /_cluster/health`
- **THEN** the trap SHALL respond with a JSON body showing status "green" and log the request

### Requirement: Session logging
Each Elasticsearch connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`elasticsearch`), and action (`connect`, `command`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext` and `DestPortFromContext(r.Context())`, not from the config value.

#### Scenario: Single-port destPort
- **WHEN** the Elasticsearch trap listens on `:9200` and a connection arrives
- **THEN** the session's dest_port is 9200, derived from `r.Context()`

#### Scenario: Multi-port destPort
- **WHEN** the Elasticsearch trap listens on `[":9200", ":9300"]` and a connection arrives on port 9300
- **THEN** the session's dest_port is 9300, derived from `r.Context()`
