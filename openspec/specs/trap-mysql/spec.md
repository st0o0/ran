## Purpose

MySQL honeypot trap emulating the MySQL wire protocol handshake to capture credentials from database scanners and brute-force tools.

## Requirements

### Requirement: MySQL handshake emulation
The MySQL trap SHALL implement the MySQL wire protocol handshake: Initial Handshake packet -> Handshake Response -> ERR packet (Access Denied).

#### Scenario: Scanner connection
- **WHEN** a MySQL client or scanner connects
- **THEN** it receives a valid MySQL greeting, sends credentials, and receives an Access Denied error

### Requirement: mysql_clear_password auth plugin
The greeting packet SHALL advertise `mysql_clear_password` as the auth plugin to encourage clients to send plaintext credentials.

#### Scenario: Plaintext credential capture
- **WHEN** a client complies with `mysql_clear_password`
- **THEN** the username and plaintext password are extracted and logged

#### Scenario: Client uses different auth plugin
- **WHEN** a client sends a hashed response (e.g. `mysql_native_password`)
- **THEN** the username is logged, the auth response is logged as hex, and the connection is closed with Access Denied

### Requirement: Realistic greeting
The greeting packet SHALL include a realistic server version string (e.g. `5.7.99-ran`), a valid connection ID, and a random auth challenge.

#### Scenario: Server version
- **WHEN** a client connects
- **THEN** the greeting contains a MySQL 5.7-compatible version string and a random 20-byte challenge

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
