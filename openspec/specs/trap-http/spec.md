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
Each HTTP request SHALL be logged with: session_id, source_ip, source_port, protocol (`http`), method, path, and action (`connect` for GET, `auth_attempt` for credential POST, `disconnect`).

#### Scenario: Credential POST logging
- **WHEN** an attacker POSTs credentials to `/wp-login.php`
- **THEN** a log entry with action `auth_attempt`, username, and password is emitted

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
The HTTP trap SHALL call `alerter.Alert()` with the source IP and protocol `http` on every credential POST.

#### Scenario: HTTP credential POST triggers alert
- **WHEN** an attacker POSTs credentials to a login page
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "http")` is called
