## Purpose

Configurable multi-authentication retry support for one-shot handlers, allowing multiple credential capture attempts per session.

## Requirements

### Requirement: Configurable multi-auth retries
One-shot handlers (SSH, Telnet, MSSQL, SMB, VNC) SHALL allow multiple authentication attempts per session, controlled by `RAN_MAX_AUTH_RETRIES` (global default, default `3`) and `RAN_<PROTO>_MAX_AUTH_RETRIES` (per-protocol override). A value of `0` SHALL mean unlimited retries (bounded only by session timeout).

#### Scenario: Global default applies
- **WHEN** `RAN_MAX_AUTH_RETRIES=3` is set and no per-protocol override exists
- **THEN** the Telnet handler SHALL allow 3 login attempts before closing the connection

#### Scenario: Per-protocol override
- **WHEN** `RAN_MAX_AUTH_RETRIES=3` and `RAN_SSH_MAX_AUTH_RETRIES=6` are set
- **THEN** the SSH handler SHALL allow 6 auth attempts while other handlers allow 3

#### Scenario: Unlimited retries
- **WHEN** `RAN_MSSQL_MAX_AUTH_RETRIES=0` is set
- **THEN** the MSSQL handler SHALL allow unlimited login attempts until session timeout or client disconnect

#### Scenario: Client disconnects before max retries
- **WHEN** a client disconnects after 2 of 6 allowed attempts
- **THEN** the handler SHALL end the session with outcome `"completed"` and log 2 auth_attempts

### Requirement: Auth retry loop pattern
Handlers implementing multi-auth SHALL loop their auth capture logic, sending a failure response after each attempt, and accepting a new attempt until the retry limit is reached or the session deadline expires.

#### Scenario: Telnet retry loop
- **WHEN** a Telnet client connects and the max retries is 3
- **THEN** the handler SHALL prompt `"Login:"` and `"Password:"` three times, responding with `"Login incorrect"` after each, before closing

#### Scenario: MSSQL retry loop
- **WHEN** an MSSQL client completes the prelogin handshake and max retries is 3
- **THEN** the handler SHALL accept up to 3 Login7 packets, responding with a TDS error after each

#### Scenario: SMB retry loop
- **WHEN** an SMB client completes negotiate and max retries is 3
- **THEN** the handler SHALL accept up to 3 Session Setup requests, responding with STATUS_LOGON_FAILURE after each

#### Scenario: Timeout during retry loop
- **WHEN** the session deadline expires during a retry loop
- **THEN** the handler SHALL end the session with outcome `"timeout"`

### Requirement: SSH multi-auth via MaxAuthTries
The SSH handler SHALL set `gossh.ServerConfig.MaxAuthTries` to the resolved max auth retries value for SSH. The `PasswordCallback` SHALL fire once per client attempt, up to the configured limit, within a single `NewServerConn` call.

#### Scenario: SSH allows 6 attempts
- **WHEN** `RAN_SSH_MAX_AUTH_RETRIES=6` is set and a client sends 6 password attempts
- **THEN** the `PasswordCallback` SHALL fire 6 times, capturing all 6 credential pairs

#### Scenario: SSH default retries
- **WHEN** no SSH-specific override is set and `RAN_MAX_AUTH_RETRIES=3` is the global default
- **THEN** `MaxAuthTries` SHALL be set to 3
