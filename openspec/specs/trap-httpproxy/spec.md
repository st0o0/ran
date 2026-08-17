## Purpose

HTTP proxy honeypot trap that simulates an open HTTP proxy to capture proxy requests and authentication credentials.

## Requirements

### Requirement: HTTP proxy request capture
The HTTP proxy trap SHALL listen on TCP as an HTTP server, detect CONNECT and proxied GET/POST requests, log the target URL/host, and respond with 407 Proxy Authentication Required.

#### Scenario: CONNECT tunnel request
- **WHEN** a client sends `CONNECT evil.com:443 HTTP/1.1`
- **THEN** the trap SHALL log the proxy request with target="evil.com:443", alert CrowdSec, and respond with `407 Proxy Authentication Required`

#### Scenario: Proxied GET request
- **WHEN** a client sends `GET http://example.com/path HTTP/1.1`
- **THEN** the trap SHALL log the request with target URL, and respond with `407 Proxy Authentication Required`

#### Scenario: Proxy-Authorization header capture
- **WHEN** a client includes a `Proxy-Authorization` header
- **THEN** the trap SHALL decode and log the credentials, alert CrowdSec, and still respond with 407

### Requirement: Session logging
Each HTTP proxy connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`httpproxy`), and action (`connect`, `auth_attempt`, `command`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext` and `DestPortFromContext(r.Context())`, not from the config value.

#### Scenario: Single-port destPort
- **WHEN** the HTTPProxy trap listens on `:8080` and a connection arrives
- **THEN** the session's dest_port is 8080, derived from `r.Context()`

#### Scenario: Multi-port destPort
- **WHEN** the HTTPProxy trap listens on `[":8080", ":3128"]` and a connection arrives on port 3128
- **THEN** the session's dest_port is 3128, derived from `r.Context()`
