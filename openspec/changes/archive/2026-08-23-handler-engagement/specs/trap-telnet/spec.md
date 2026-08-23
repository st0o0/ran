## MODIFIED Requirements

### Requirement: Telnet login prompt and credential capture
The Telnet trap SHALL listen on TCP, present a login prompt, capture username and password, log the credentials, display "Login incorrect", and repeat up to the resolved max auth retries. The session timeout SHALL use the resolved value for Telnet (global default or `RAN_TELNET_SESSION_TIMEOUT` override).

#### Scenario: Single credential capture
- **WHEN** a client connects and provides username "root" and password "toor"
- **THEN** the trap SHALL log an auth_attempt with those credentials, alert CrowdSec, and display "Login incorrect"

#### Scenario: Multiple credential captures
- **WHEN** `RAN_MAX_AUTH_RETRIES=3` and a client provides 3 different credential pairs
- **THEN** the trap SHALL log 3 auth_attempts, alert CrowdSec 3 times, and display "Login incorrect" after each

#### Scenario: Max retries reached
- **WHEN** the client has exhausted all allowed retries
- **THEN** the trap SHALL close the connection with outcome `"completed"`

#### Scenario: Client disconnects mid-retry
- **WHEN** a client disconnects after 1 of 3 allowed attempts
- **THEN** the trap SHALL end the session with outcome `"completed"` and 1 auth_attempt logged

## ADDED Requirements

### Requirement: Telnet auth delay
The Telnet handler SHALL apply the resolved auth delay for Telnet before sending "Login incorrect" on each attempt, using the shared `authSleep` helper with escalating backoff.

#### Scenario: Delay between Telnet attempts
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client makes 3 attempts
- **THEN** the delays before each "Login incorrect" response SHALL be: 2s, 4s, 8s

#### Scenario: No delay when disabled
- **WHEN** `RAN_AUTH_DELAY` is not set (default 0s)
- **THEN** "Login incorrect" SHALL be sent immediately after credential capture
