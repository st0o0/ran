## MODIFIED Requirements

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

### Requirement: Session timeout
Connections SHALL be closed after the resolved session timeout for SSH (default `RAN_SESSION_TIMEOUT`, overridable by `RAN_SSH_SESSION_TIMEOUT`) regardless of client activity.

#### Scenario: Idle connection
- **WHEN** a client connects but sends no auth attempt for the configured timeout
- **THEN** the connection is closed and a disconnect event is logged

#### Scenario: Extended timeout for tarpit
- **WHEN** `RAN_SSH_SESSION_TIMEOUT=120s` is set
- **THEN** the SSH session deadline SHALL be 120s, allowing time for tarpit + auth phases

### Requirement: CrowdSec alert on auth attempt
The SSH trap SHALL call `alerter.Alert()` with the source IP and protocol `ssh` on every auth_attempt. With multi-auth enabled, this SHALL fire once per attempt.

#### Scenario: SSH auth triggers alert
- **WHEN** an attacker attempts SSH password auth
- **THEN** `alerter.Alert(ctx, "1.2.3.4", "ssh")` is called

#### Scenario: Multiple alerts per session
- **WHEN** an attacker makes 6 password attempts in one session
- **THEN** `alerter.Alert()` SHALL be called 6 times

## ADDED Requirements

### Requirement: SSH auth delay
The SSH handler SHALL apply the resolved auth delay for SSH between password attempts. The delay SHALL be applied within the PasswordCallback before returning the auth failure, using the shared `authSleep` helper.

#### Scenario: Delay between SSH attempts
- **WHEN** `RAN_SSH_AUTH_DELAY=3s` is set and a client makes 3 attempts
- **THEN** the delays before each rejection SHALL be: 3s, 6s, 12s (capped at 4× base = 12s)

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
