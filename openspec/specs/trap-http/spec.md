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

### Requirement: Request logging
The HTTP trap SHALL log every request with method, path without query string, `Host`, `User-Agent` and a bounded header subset. Values SHALL be cut to 256 bytes and stripped of control characters.

#### Scenario: Plain GET
- **WHEN** a client sends `GET /index.html` with `User-Agent: zgrab/0.x`
- **THEN** a `probe` log entry with method, path and user agent is emitted and the session stays a probe

#### Scenario: Oversized header value
- **WHEN** a `User-Agent` longer than 256 bytes is sent
- **THEN** the logged value is cut to 256 bytes

### Requirement: Exploit path classification
A request whose path matches the built-in exploit path list, or whose request line or header values contain a JNDI lookup string, SHALL be recorded as a command and counted as `attack`.

#### Scenario: Secrets file probe
- **WHEN** a client requests `GET /.env`
- **THEN** a command is logged with the path and the session is classified `attack`

#### Scenario: JNDI in header
- **WHEN** a request carries `X-Api-Version: ${jndi:ldap://x/a}`
- **THEN** a command is logged and the session is classified `attack`

#### Scenario: Ordinary path
- **WHEN** a client requests `GET /robots.txt`
- **THEN** the session stays a `probe` and no alert is raised

### Requirement: Basic authorization capture
A request with an HTTP Basic `Authorization` header SHALL be recorded as an auth attempt with the decoded username (a value without a colon is a bare username; invalid base64 is ignored). The password SHALL follow `RAN_LOG_PASSWORDS` and never becomes alert meta.

#### Scenario: Basic credentials
- **WHEN** a client sends `Authorization: Basic YWRtaW46aHVudGVyMg==`
- **THEN** an auth attempt for user `admin` is logged and the session is classified `attack`

### Requirement: Non-form body as payload
A `POST`, `PUT` or `PATCH` body that is not a form login SHALL be read up to the 16 KiB limit and counted as payload bytes. A form login is a `POST` with an `application/x-www-form-urlencoded` body that has a credential field, or a `POST` with an empty body; both keep the existing auth attempt behavior.

#### Scenario: JSON body
- **WHEN** a client POSTs a 300 byte JSON body to `/api/login`
- **THEN** 300 payload bytes are recorded and the session is classified `attack`

