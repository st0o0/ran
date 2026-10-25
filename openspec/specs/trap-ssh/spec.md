## Purpose

SSH honeypot trap emulating an OpenSSH server to capture credentials from brute-force attacks and scanners.
## Requirements
### Requirement: SSH server emulation
The SSH trap SHALL use `golang.org/x/crypto/ssh` with a `ServerConfig` that accepts password authentication via a callback. The `ServerConfig.MaxAuthTries` SHALL be set to the resolved max auth retries value for SSH. The PasswordCallback SHALL capture credentials on each attempt. After `NewServerConn` returns, the outcome SHALL be `"completed"` if at least one auth attempt was processed, or classified by error type otherwise.

#### Scenario: Brute-force connection with multiple attempts
- **WHEN** an attacker connects and attempts 6 password auths with different credentials
- **THEN** the trap logs all 6 credential pairs, returns auth failure for each, and closes the connection with outcome `"completed"`

#### Scenario: Handshake failure without auth
- **WHEN** a client connects but the SSH handshake fails before any password attempt (e.g., key exchange mismatch)
- **THEN** the trap sets outcome `"error"` and logs a handshake_failed error

#### Scenario: Handshake timeout without auth
- **WHEN** a client connects but sends no data until the session deadline expires
- **THEN** the trap sets outcome `"timeout"`

### Requirement: Host key management
The trap SHALL generate an Ed25519 host key at startup. If `/data/ssh_host_key` exists, it SHALL be loaded instead. If `/data/` is writable and no key file exists, the generated key SHALL be persisted there.

#### Scenario: Fresh start without volume
- **WHEN** `/data/` does not exist or is not writable
- **THEN** an ephemeral Ed25519 key is generated and used for the session

#### Scenario: Persistent key
- **WHEN** `/data/ssh_host_key` exists
- **THEN** the key is loaded from disk and reused across restarts

### Requirement: Session logging
Each SSH connection SHALL be logged with: session_id, source_ip, source_port, protocol (`ssh`), and action (`connect`, `auth_attempt`, `disconnect`). Auth attempts SHALL include username and password.

#### Scenario: Log output
- **WHEN** an attacker connects from 1.2.3.4:54321 and tries `root`/`password`
- **THEN** three log entries are emitted: connect, auth_attempt (with credentials), disconnect

### Requirement: Session timeout
Connections SHALL be closed after the resolved session timeout for SSH (default `RAN_SESSION_TIMEOUT`, overridable by `RAN_SSH_SESSION_TIMEOUT`) regardless of client activity.

#### Scenario: Idle connection
- **WHEN** a client connects but sends no auth attempt for the configured timeout
- **THEN** the connection is closed and a disconnect event is logged

#### Scenario: Extended timeout for tarpit
- **WHEN** `RAN_SSH_SESSION_TIMEOUT=120s` is set
- **THEN** the SSH session deadline SHALL be 120s, allowing time for tarpit + auth phases

### Requirement: Banner
The SSH trap SHALL present a realistic server banner (e.g. `SSH-2.0-OpenSSH_9.6`).

#### Scenario: Banner exchange
- **WHEN** a client connects
- **THEN** the server sends an OpenSSH-style banner string

### Requirement: CrowdSec alert on auth attempt
The SSH trap SHALL call `alerter.Alert()` with the source IP and protocol `ssh` on every auth_attempt. With multi-auth enabled, this SHALL fire once per attempt.

#### Scenario: SSH auth triggers alert
- **WHEN** an attacker attempts SSH password auth
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "ssh")` is called

#### Scenario: Multiple alerts per session
- **WHEN** an attacker makes 6 password attempts in one session
- **THEN** `alerter.Alert()` SHALL be called 6 times

### Requirement: SSH auth delay
The SSH handler SHALL apply the resolved auth delay for SSH between password attempts. The delay SHALL be applied within the PasswordCallback before returning the auth failure, using the shared `authSleep` helper.

#### Scenario: Delay between SSH attempts
- **WHEN** `RAN_SSH_AUTH_DELAY=3s` is set and a client makes 3 attempts
- **THEN** the delays before each rejection SHALL be: 3s, 6s, 12s (capped at 4x base = 12s)

#### Scenario: No delay when disabled
- **WHEN** `RAN_SSH_AUTH_DELAY` is not set (default 0s)
- **THEN** password rejections SHALL be returned immediately

### Requirement: SSH pre-auth tarpit integration
When `RAN_SSH_TARPIT=on`, the SSH handler SHALL execute the tarpit phase on the raw connection before passing it to `gossh.NewServerConn`. The tarpit phase SHALL send random banner lines at 10-second intervals for `RAN_SSH_TARPIT_DURATION`.

#### Scenario: Tarpit before auth
- **WHEN** `RAN_SSH_TARPIT=on` and `RAN_SSH_TARPIT_DURATION=20s` are set
- **THEN** the handler SHALL send random lines for 20s, then proceed with normal SSH handshake and auth

#### Scenario: Tarpit disabled
- **WHEN** `RAN_SSH_TARPIT=off`
- **THEN** the handler SHALL proceed directly to SSH handshake

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


### Requirement: Era-appropriate algorithms
The server SHALL offer only key exchange, cipher and MAC algorithms that the OpenSSH releases of the banner profiles (8.2 to 9.6) offered and that the SSH library implements, and SHALL NOT offer `mlkem768x25519-sha256` (OpenSSH 9.9) or `sntrup761x25519-sha512@openssh.com`. The host key is ed25519 only.

#### Scenario: Server KEXINIT
- **WHEN** a client reads the server SSH_MSG_KEXINIT
- **THEN** the key exchange list starts with `curve25519-sha256` and contains no `mlkem` entry, and a client limited to one of the offered algorithms completes the handshake
