## MODIFIED Requirements

### Requirement: MSSQL TDS credential capture
The MSSQL trap SHALL listen on TCP, handle the TDS prelogin handshake, then accept TDS Login7 packets in a loop up to the resolved max auth retries, extracting credentials and responding with a TDS error token after each attempt. Connections that do not send a valid TDS prelogin as the first packet SHALL be classified with outcome `"probe"`.

#### Scenario: Login7 credential capture with retries
- **WHEN** a client sends a TDS prelogin followed by 3 Login7 packets with different credentials
- **THEN** the trap SHALL log 3 auth_attempts, alert CrowdSec 3 times, and respond with a TDS error after each

#### Scenario: Single Login7 (legacy behavior)
- **WHEN** a client sends a TDS prelogin followed by 1 Login7 and then disconnects
- **THEN** the trap SHALL log 1 auth_attempt with outcome `"completed"`

#### Scenario: Prelogin handshake
- **WHEN** a client sends a TDS prelogin request
- **THEN** the trap SHALL respond with a valid prelogin response indicating version and encryption support

#### Scenario: Non-TDS connection (scanner probe)
- **WHEN** a client connects and sends data that is not a TDS prelogin packet (first byte is not `0x12`)
- **THEN** the trap SHALL set outcome `"probe"` and close the connection

#### Scenario: Invalid packet length (scanner probe)
- **WHEN** a client sends a packet with an invalid TDS length (< 8 or > 1MB)
- **THEN** the trap SHALL set outcome `"probe"` and close the connection

## ADDED Requirements

### Requirement: MSSQL auth delay
The MSSQL handler SHALL apply the resolved auth delay for MSSQL before sending the TDS error response on each attempt, using the shared `authSleep` helper with escalating backoff.

#### Scenario: Delay between MSSQL attempts
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client makes 3 Login7 attempts
- **THEN** the delays before each TDS error response SHALL be: 2s, 4s, 8s

#### Scenario: No delay when disabled
- **WHEN** `RAN_AUTH_DELAY` is not set (default 0s)
- **THEN** TDS error responses SHALL be sent immediately
