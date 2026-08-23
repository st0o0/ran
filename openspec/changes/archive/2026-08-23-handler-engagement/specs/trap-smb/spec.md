## MODIFIED Requirements

### Requirement: SMB negotiate and session setup capture
The SMB trap SHALL listen on TCP, handle SMB/SMB2 Negotiate, respond with a Negotiate response, then accept Session Setup requests in a loop up to the resolved max auth retries, logging each authentication attempt and responding with STATUS_LOGON_FAILURE. Connections that do not send a valid SMB message (no `0xFF SMB` or `0xFE SMB` header after NetBIOS framing) SHALL be classified with outcome `"probe"`.

#### Scenario: SMB2 session setup capture with retries
- **WHEN** a client sends an SMB2 Negotiate followed by 3 Session Setup requests with NTLMSSP authentication
- **THEN** the trap SHALL extract and log credentials from each, alert CrowdSec 3 times, and respond with STATUS_LOGON_FAILURE after each

#### Scenario: Single session setup (legacy behavior)
- **WHEN** a client sends Negotiate followed by 1 Session Setup and then disconnects
- **THEN** the trap SHALL log 1 auth_attempt with outcome `"completed"`

#### Scenario: SMB1 negotiate
- **WHEN** a client sends an SMB1 Negotiate
- **THEN** the trap SHALL respond with a valid SMB1 Negotiate response selecting NT LM 0.12 dialect

#### Scenario: SMB2 negotiate
- **WHEN** a client sends an SMB2 Negotiate
- **THEN** the trap SHALL respond selecting SMB 2.1 dialect with NTLMSSP security

#### Scenario: Non-SMB connection (scanner probe)
- **WHEN** a client connects and sends data that does not contain a valid SMB header
- **THEN** the trap SHALL set outcome `"probe"` and close the connection

## ADDED Requirements

### Requirement: SMB auth delay
The SMB handler SHALL apply the resolved auth delay for SMB before sending STATUS_LOGON_FAILURE on each Session Setup attempt, using the shared `authSleep` helper with escalating backoff.

#### Scenario: Delay between SMB attempts
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client makes 3 Session Setup attempts
- **THEN** the delays before each STATUS_LOGON_FAILURE response SHALL be: 2s, 4s, 8s

#### Scenario: No delay when disabled
- **WHEN** `RAN_AUTH_DELAY` is not set (default 0s)
- **THEN** STATUS_LOGON_FAILURE responses SHALL be sent immediately
