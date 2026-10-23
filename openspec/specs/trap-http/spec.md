## Purpose

HTTP honeypot trap serving fake login pages on common admin paths, capturing credentials from POST submissions, and logging all interactions.
## Requirements
### Requirement: Fake login pages
The HTTP trap SHALL serve realistic HTML login pages on common admin paths: `/admin`, `/wp-login.php`, and `/` (catch-all).

#### Scenario: GET /wp-login.php
- **WHEN** an attacker requests `GET /wp-login.php`
- **THEN** a WordPress-style login form is returned with HTTP 200

#### Scenario: GET /admin
- **WHEN** an attacker requests `GET /admin`
- **THEN** a generic admin login form is returned with HTTP 200

### Requirement: Credential capture
The trap SHALL capture POST form data containing credentials (fields: `username`/`user`/`log`, `password`/`pass`/`pwd`).

#### Scenario: POST /wp-login.php
- **WHEN** an attacker submits `log=admin&pwd=password123` via POST
- **THEN** the credentials are logged, and a login-failed page is returned

### Requirement: Session logging
Each HTTP connection SHALL be logged with: session_id, source_ip, source_port, dest_port, protocol (`http`), and action (`connect`, `auth_attempt`, `disconnect`). The dest_port SHALL be derived from the connection's local address via `ConnContext`, not from the config value.

#### Scenario: Credential POST logging
- **WHEN** an attacker POSTs credentials to `/wp-login.php`
- **THEN** a log entry with action `auth_attempt`, username, and password is emitted

#### Scenario: Single-port destPort
- **WHEN** the HTTP trap listens on `:8081` and a connection arrives
- **THEN** the session's dest_port is 8081, derived from `ConnContext`

#### Scenario: Multi-port destPort
- **WHEN** the HTTP trap listens on `[":8081", ":8443"]` and a connection arrives on port 8443
- **THEN** the session's dest_port is 8443, derived from `ConnContext`

### Requirement: Realistic responses
Login failure responses SHALL look like the real service (WordPress-style error for `/wp-login.php`, generic "invalid credentials" for `/admin`). HTTP headers SHALL mimic a typical web server.

#### Scenario: Response headers
- **WHEN** any request is served
- **THEN** response includes realistic `Server` and `Content-Type` headers

### Requirement: Session timeout
HTTP connections SHALL respect `RAN_SESSION_TIMEOUT` via the server's `ReadTimeout` and `WriteTimeout`.

#### Scenario: Slow client
- **WHEN** a client connects but sends the request body slowly beyond the timeout
- **THEN** the server closes the connection

### Requirement: CrowdSec alert on credential capture
The HTTP trap SHALL call `alerter.Alert()` with the socket peer IP and protocol `http` on every credential POST. The `X-Real-IP` and `X-Forwarded-For` headers SHALL NOT influence the alert IP; a syntactically valid header IP SHALL be logged in a separate `claimed_client_ip` field.

#### Scenario: HTTP credential POST triggers alert
- **WHEN** an attacker POSTs credentials to a login page
- **THEN** `alerter.Alert(ctx, <peer IP>, "http", ...)` is called

#### Scenario: Spoofed forwarding header
- **WHEN** a POST from peer `198.51.100.7` carries `X-Forwarded-For: 203.0.113.9`
- **THEN** the alert IP is `198.51.100.7` and the log contains `claimed_client_ip=203.0.113.9`

#### Scenario: Garbage header
- **WHEN** `X-Real-IP` is `not-an-ip`
- **THEN** the alert IP is the peer IP and no `claimed_client_ip` field is logged

### Requirement: Request body limit
The HTTP trap SHALL wrap the request body with `http.MaxBytesReader` (16 KiB) before parsing forms and SHALL set `MaxHeaderBytes` to 16 KiB.

#### Scenario: Oversized POST
- **WHEN** a client POSTs a body larger than 16 KiB
- **THEN** form parsing fails, credentials are empty and memory use stays bounded

