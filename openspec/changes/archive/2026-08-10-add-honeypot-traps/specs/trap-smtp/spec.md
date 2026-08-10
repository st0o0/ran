## ADDED Requirements

### Requirement: SMTP banner and AUTH credential capture
The SMTP trap SHALL listen on TCP, send a `220` SMTP banner, handle EHLO/HELO, advertise AUTH LOGIN/PLAIN, capture credentials from AUTH attempts, and reject with `535 Authentication failed`.

#### Scenario: AUTH LOGIN credential capture
- **WHEN** a client sends EHLO, then `AUTH LOGIN`, then base64-encoded username and password
- **THEN** the trap SHALL decode and log the credentials, alert CrowdSec, and respond with `535 5.7.8 Authentication failed`

#### Scenario: EHLO response
- **WHEN** a client sends `EHLO example.com`
- **THEN** the trap SHALL respond with `250` and advertise `AUTH LOGIN PLAIN` capability

#### Scenario: Relay attempt without auth
- **WHEN** a client sends `MAIL FROM:` without authenticating
- **THEN** the trap SHALL respond with `530 5.7.1 Authentication required`
