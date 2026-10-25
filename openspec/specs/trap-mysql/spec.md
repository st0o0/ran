## Purpose

MySQL honeypot trap emulating the MySQL wire protocol handshake to capture credentials from database scanners and brute-force tools.

## Requirements

### Requirement: MySQL handshake emulation
The MySQL trap SHALL implement the MySQL wire protocol handshake: Initial Handshake packet -> Handshake Response -> ERR packet (Access Denied).

#### Scenario: Scanner connection
- **WHEN** a MySQL client or scanner connects
- **THEN** it receives a valid MySQL greeting, sends credentials, and receives an Access Denied error

### Requirement: mysql_clear_password auth plugin
In fixed mode the greeting packet SHALL advertise `mysql_clear_password` as the auth plugin to encourage clients to send plaintext credentials. In seeded mode the greeting advertises the default plugin of the profile's MySQL generation (see "Realistic greeting") and the trap SHALL obtain the plaintext password with an authentication switch to `mysql_clear_password` after the client's first response, when the client set CLIENT_PLUGIN_AUTH.

#### Scenario: Plaintext credential capture
- **WHEN** a client complies with `mysql_clear_password` (directly in fixed mode, after the switch in seeded mode)
- **THEN** the username and plaintext password are extracted and logged

#### Scenario: Client uses different auth plugin
- **WHEN** a client sends a scramble (e.g. `mysql_native_password`) and does not follow the switch
- **THEN** no scramble is recorded as a password, the connection is closed with Access Denied, and the session counts as exactly one login attempt without a password (see "Scramble is not a credential")

### Requirement: Scramble is not a credential
In seeded mode the first response to a greeting that names a scramble plugin (`mysql_native_password`, `caching_sha2_password`, `sha256_password`) SHALL NOT be recorded as a credential: no `auth_attempt` log line, no credential metric and no alert for it. The username of that response is kept only as session identity until the clear text round. The authentication switch to `mysql_clear_password` that follows SHALL NOT count as a password attempt against `RAN_MAX_AUTH_RETRIES`, so the clear text is asked for even when the limit is `1`; real passwords are counted from the first clear text reply on, and the repeat password guard applies to them. A reply is taken as a clear text password only if it is NUL terminated. If the client does not deliver a clear text password (it closes the connection, stalls until the timeout or replies with another scramble), the session SHALL count as exactly one login attempt without a password: one `auth_attempt` log line with the username and no password field, and, only if the username is not empty, one captured credential and one alert whose meta holds the username and no password. With an empty username the `auth_attempt` line is still written but nothing is counted or alerted. Fixed mode, whose greeting names `mysql_clear_password`, SHALL keep recording one credential with the clear password from the first response.

#### Scenario: Scramble then clear password
- **WHEN** a seeded 8.0 or 5.7 trap receives a scramble, sends the switch and the client replies with a clear text password
- **THEN** exactly one credential (the clear text password) is logged, counted and alerted

#### Scenario: Client hangs up after the scramble
- **WHEN** the client closes the connection after the authentication switch
- **THEN** one `auth_attempt` without a password is logged, one credential is counted and one alert with the username only is raised

### Requirement: Realistic greeting
The greeting packet SHALL include the server version string of the profile, a valid connection ID, and a random auth challenge without NUL bytes. In seeded mode it SHALL depend on the major version: 8.0.x advertises `caching_sha2_password`, charset 255 (utf8mb4_0900_ai_ci) and capability flags `0xf7ff`/`0xc3ff`; 5.7.x advertises `mysql_native_password`, charset 8 (latin1_swedish_ci) and flags `0xf7ff`/`0x807f`. CLIENT_SSL is not advertised because the trap has no TLS. Fixed mode SHALL keep the byte-for-byte greeting of earlier releases.

#### Scenario: Server version
- **WHEN** a client connects to a trap with an 8.0 profile
- **THEN** the greeting names `caching_sha2_password` and a 20-byte challenge

### Requirement: Session logging
Each MySQL connection SHALL be logged with: session_id, source_ip, source_port, protocol (`mysql`), and action (`connect`, `auth_attempt`, `disconnect`). Auth attempts SHALL include username and password (if plaintext) or auth_data (if hashed).

#### Scenario: Log output
- **WHEN** a scanner connects from 1.2.3.4:54321 and sends credentials
- **THEN** connect, auth_attempt, and disconnect events are logged with the session_id

### Requirement: Session timeout
Connections SHALL be closed after `RAN_SESSION_TIMEOUT` if the client does not complete the handshake.

#### Scenario: Stalled handshake
- **WHEN** a client connects but never sends the Handshake Response
- **THEN** the connection is closed after the timeout

### Requirement: CrowdSec alert on auth attempt
The MySQL trap SHALL call `alerter.Alert()` with the source IP and protocol `mysql` on every auth_attempt.

#### Scenario: MySQL auth triggers alert
- **WHEN** an attacker completes the MySQL handshake
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "mysql")` is called
