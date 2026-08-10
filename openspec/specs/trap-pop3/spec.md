## Purpose

POP3 honeypot trap that simulates a POP3 mail server to capture unauthorized access attempts and credential harvesting.

## Requirements

### Requirement: POP3 credential capture
The POP3 trap SHALL listen on TCP, send a `+OK` banner, accept USER and PASS commands, log the credentials, and respond with `-ERR Authentication failed`.

#### Scenario: Credential capture
- **WHEN** a client sends `USER admin` then `PASS secret`
- **THEN** the trap SHALL log auth_attempt with those credentials, alert CrowdSec, and respond with `-ERR [AUTH] Authentication failed`

#### Scenario: Banner
- **WHEN** a client connects
- **THEN** the trap SHALL send `+OK POP3 server ready\r\n`
