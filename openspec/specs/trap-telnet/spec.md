## Purpose

Telnet honeypot trap that simulates a Telnet login service to capture unauthorized access attempts and credential harvesting.
## Requirements
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

#### Scenario: Banner display
- **WHEN** a client connects
- **THEN** the trap SHALL send a system banner (e.g., hostname/OS identification) followed by a `login:` prompt

### Requirement: Telnet auth delay
The Telnet handler SHALL apply the resolved auth delay for Telnet before sending "Login incorrect" on each attempt, using the shared `authSleep` helper with escalating backoff.

#### Scenario: Delay between Telnet attempts
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client makes 3 attempts
- **THEN** the delays before each "Login incorrect" response SHALL be: 2s, 4s, 8s

#### Scenario: No delay when disabled
- **WHEN** `RAN_AUTH_DELAY` is not set (default 0s)
- **THEN** "Login incorrect" SHALL be sent immediately after credential capture

### Requirement: Option negotiation
The Telnet trap SHALL parse IAC sequences in the input, answer `DO` with `WONT` and `WILL` with `DONT`, and SHALL NOT pass IAC bytes into the username or password.

#### Scenario: Mirai-style client
- **WHEN** a client sends `FF FB 18` followed by `root\r\n`
- **THEN** the username is `root` and a `DONT` reply for the option was sent

#### Scenario: Truncated sequence
- **WHEN** the input ends inside an IAC sequence
- **THEN** the sequence is dropped and the session ends normally

#### Scenario: Reply bound
- **WHEN** a line carries more options than fit in 192 bytes of replies
- **THEN** the surplus options are dropped without an answer

### Requirement: Terminal type
If a client reports a terminal type via subnegotiation, the trap SHALL log it bounded to 64 bytes.

#### Scenario: TTYPE reply
- **WHEN** a client sends `IAC SB TTYPE IS xterm IAC SE`
- **THEN** `xterm` is logged as the terminal type

