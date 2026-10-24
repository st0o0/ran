## ADDED Requirements

### Requirement: Public key capture
The SSH trap SHALL set a `PublicKeyCallback` that logs the user, key type and SHA256 fingerprint of every distinct offered key (a key offered again for the same user is not logged again) as an auth attempt, raises the usual alert and always rejects the key.

#### Scenario: Key-only bot
- **WHEN** a client offers an ed25519 key for user `root`
- **THEN** an auth attempt with the fingerprint is logged, an alert is raised and the key is rejected

#### Scenario: Limit
- **WHEN** a client offers more keys than `MaxAuthTries` allows
- **THEN** the connection ends after the configured number of attempts

### Requirement: Keyboard-interactive capture
The SSH trap SHALL capture keyboard-interactive answers as a credential attempt and always reject them. The password SHALL be logged according to `RAN_LOG_PASSWORDS`. A failed exchange (wrong number of answers, client hangs up mid-prompt) SHALL still be recorded as an attempt without a password.

#### Scenario: Interactive login
- **WHEN** a client answers a keyboard-interactive prompt with `hunter2`
- **THEN** an auth attempt is logged and rejected and no password reaches CrowdSec

### Requirement: Client identity
The trap SHALL log the client version string and the HASSH of the client key exchange offer and add `client_version` and `hassh` to the alert meta of every auth attempt. HASSH SHALL be computed from the client SSH_MSG_KEXINIT by a read-only, size-bounded tap on the connection. Values SHALL be bounded.

#### Scenario: Version string
- **WHEN** a client announces `SSH-2.0-libssh_0.9.6`
- **THEN** the log and alert meta contain `client_version=SSH-2.0-libssh_0.9.6`

#### Scenario: Oversized version string
- **WHEN** the client version contains control characters or is longer than 255 bytes (the SSH library itself ends the handshake beyond 255 bytes)
- **THEN** only printable ASCII is kept and the value is cut to 255 bytes before logging and alerting
