## ADDED Requirements

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
