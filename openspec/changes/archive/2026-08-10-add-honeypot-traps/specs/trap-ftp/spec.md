## ADDED Requirements

### Requirement: FTP banner and credential capture
The FTP trap SHALL listen on TCP, send a `220` welcome banner identifying as a generic FTP server, accept `USER` and `PASS` commands, log the credentials, and respond with `530 Login incorrect`.

#### Scenario: Successful credential capture
- **WHEN** a client connects and sends `USER admin` followed by `PASS secret`
- **THEN** the trap SHALL log an auth_attempt with username="admin" and password="secret", alert CrowdSec, and respond with `530 Login incorrect`

#### Scenario: Banner exchange
- **WHEN** a client connects
- **THEN** the trap SHALL send `220 FTP Server ready.\r\n` and wait for commands

#### Scenario: Unexpected command before auth
- **WHEN** a client sends a command other than USER/PASS (e.g., LIST)
- **THEN** the trap SHALL respond with `530 Please login with USER and PASS.\r\n`
