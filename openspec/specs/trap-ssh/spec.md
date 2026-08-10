## Purpose

SSH honeypot trap emulating an OpenSSH server to capture credentials from brute-force attacks and scanners.

## Requirements

### Requirement: SSH server emulation
The SSH trap SHALL use `golang.org/x/crypto/ssh` with a `ServerConfig` that accepts password authentication via a callback.

#### Scenario: Brute-force connection
- **WHEN** an attacker connects and attempts password auth with username `root` and password `admin123`
- **THEN** the trap logs the credentials, returns auth failure, and closes the connection

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
Connections SHALL be closed after `RAN_SESSION_TIMEOUT` (default 30s) regardless of client activity.

#### Scenario: Idle connection
- **WHEN** a client connects but sends no auth attempt for 30 seconds
- **THEN** the connection is closed and a disconnect event is logged

### Requirement: Banner
The SSH trap SHALL present a realistic server banner (e.g. `SSH-2.0-OpenSSH_9.6`).

#### Scenario: Banner exchange
- **WHEN** a client connects
- **THEN** the server sends an OpenSSH-style banner string

### Requirement: CrowdSec alert on auth attempt
The SSH trap SHALL call `alerter.Alert()` with the source IP and protocol `ssh` on every auth_attempt.

#### Scenario: SSH auth triggers alert
- **WHEN** an attacker attempts SSH password auth
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "ssh")` is called
