## Purpose

IMAP honeypot trap that simulates an IMAP mail server to capture unauthorized access attempts and credential harvesting.

## Requirements

### Requirement: IMAP credential capture
The IMAP trap SHALL listen on TCP, send an `* OK` banner, accept LOGIN commands, log the credentials, and respond with `NO [AUTHENTICATIONFAILED]`.

#### Scenario: LOGIN credential capture
- **WHEN** a client sends `a001 LOGIN user@example.com password123`
- **THEN** the trap SHALL log auth_attempt with username="user@example.com" and password="password123", alert CrowdSec, and respond with `a001 NO [AUTHENTICATIONFAILED] Invalid credentials`

#### Scenario: Banner
- **WHEN** a client connects
- **THEN** the trap SHALL send `* OK IMAP4rev1 Server Ready\r\n`
