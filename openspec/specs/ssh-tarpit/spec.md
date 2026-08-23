## Purpose

Endlessh-style SSH pre-authentication tarpit that wastes attacker time by slowly dripping random banner lines before the real SSH handshake.

## Requirements

### Requirement: SSH pre-auth tarpit
The SSH handler SHALL support an endlessh-style pre-auth tarpit, controlled by `RAN_SSH_TARPIT` (on/off, default off) and `RAN_SSH_TARPIT_DURATION` (Go duration, default `30s`). When enabled, the handler SHALL send random banner lines before presenting the real SSH version string.

#### Scenario: Tarpit disabled
- **WHEN** `RAN_SSH_TARPIT` is not set or is `off`
- **THEN** the SSH handler SHALL immediately proceed with the normal SSH handshake

#### Scenario: Tarpit enabled
- **WHEN** `RAN_SSH_TARPIT=on` and `RAN_SSH_TARPIT_DURATION=30s` are set
- **THEN** the SSH handler SHALL send random lines for 30 seconds before sending the `SSH-2.0-OpenSSH_9.6` banner

### Requirement: Tarpit line format
Each tarpit line SHALL be a random string of 32 printable ASCII characters followed by `\r\n`. Lines SHALL NOT start with `SSH-` to avoid being parsed as the version string by clients.

#### Scenario: Line format
- **WHEN** the tarpit sends a line
- **THEN** the line SHALL match the pattern `[!-~]{32}\r\n` and SHALL NOT start with `SSH-`

#### Scenario: Line interval
- **WHEN** the tarpit is active
- **THEN** lines SHALL be sent at 10-second intervals

### Requirement: Tarpit respects session deadline
The tarpit phase SHALL respect the session deadline. If the session timeout is reached during the tarpit phase, the handler SHALL close the connection with outcome `"timeout"`.

#### Scenario: Timeout during tarpit
- **WHEN** `RAN_SSH_TARPIT_DURATION=60s` and `RAN_SESSION_TIMEOUT=30s`
- **THEN** the tarpit SHALL be interrupted at 30s by the session deadline and outcome SHALL be `"timeout"`

#### Scenario: Client disconnects during tarpit
- **WHEN** a client disconnects while the tarpit is sending lines
- **THEN** the handler SHALL detect the write error and end the session

### Requirement: Tarpit then auth flow
When the tarpit phase completes without timeout or client disconnect, the SSH handler SHALL proceed with the normal SSH handshake, including multi-auth retries and auth delay if configured.

#### Scenario: Full hybrid flow
- **WHEN** `RAN_SSH_TARPIT=on`, `RAN_SSH_TARPIT_DURATION=10s`, `RAN_SSH_MAX_AUTH_RETRIES=6`, and `RAN_SSH_AUTH_DELAY=2s` are set
- **THEN** the handler SHALL drip lines for 10s, then present the SSH banner, then allow 6 auth attempts with escalating delays
- **AND** credentials from all 6 attempts SHALL be captured
