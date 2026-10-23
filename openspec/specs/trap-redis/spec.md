## Purpose

Redis honeypot trap that simulates a Redis server to capture unauthorized commands and authentication attempts via the RESP protocol.
## Requirements
### Requirement: Redis RESP command capture
The Redis trap SHALL listen on TCP, accept RESP (Redis Serialization Protocol) commands, log each command with its arguments, and respond with `-ERR` errors.

#### Scenario: AUTH command capture
- **WHEN** a client sends `AUTH password123`
- **THEN** the trap SHALL log auth_attempt with password="password123", alert CrowdSec, and respond with `-ERR invalid password`

#### Scenario: INFO command capture
- **WHEN** a client sends `INFO`
- **THEN** the trap SHALL log a command event with command="INFO" and respond with `-ERR operation not permitted`

#### Scenario: General command logging
- **WHEN** a client sends any RESP command (GET, SET, KEYS, etc.)
- **THEN** the trap SHALL log the command name and arguments, and respond with `-NOAUTH Authentication required.\r\n`

### Requirement: Bounded RESP parsing
The Redis trap SHALL reject RESP arrays with more than 128 elements and bulk strings longer than 4096 bytes, SHALL NOT preallocate memory from client-supplied counts or lengths, and SHALL close the connection on violation.

#### Scenario: Huge array count
- **WHEN** a client sends `*2147483647\r\n`
- **THEN** the connection is closed with outcome `error` and no large allocation occurs

#### Scenario: Huge bulk length
- **WHEN** a client sends `*1\r\n$2000000000\r\n`
- **THEN** the connection is closed without allocating the announced size

#### Scenario: Normal AUTH
- **WHEN** a client sends `*2\r\n$4\r\nAUTH\r\n$3\r\nfoo\r\n`
- **THEN** the trap replies `-ERR invalid password` as before

