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

### Requirement: Retries for mysql and postgres
`mysql` and `postgres` SHALL honor `RAN_MAX_AUTH_RETRIES` and `RAN_AUTH_DELAY` (and their per-trap overrides) like `ssh`, `telnet`, `mssql` and `smb`. `0` SHALL mean unlimited attempts until the session timeout. `mysql` SHALL ask for each further attempt with an authentication switch to `mysql_clear_password` and take the clear text password from the reply. `postgres` SHALL repeat the cleartext password request after a rejected password, without an error in between, and send the error response only after the last attempt. A password identical to the previous attempt of the session SHALL NOT count as a new attempt (clients such as libpq and pgx resend their stored password): it is not logged or reported and the session ends with the normal failure response. `mysql` SHALL send the authentication switch only if the client set `CLIENT_PLUGIN_AUTH` in its handshake response; otherwise it answers ERR 1045 immediately and the session stays a single attempt. Every loop iteration SHALL block on a client read or on the auth delay, which never extends past the session deadline, so unlimited mode ends at the session timeout.

#### Scenario: Default retries
- **WHEN** a mysql client fails authentication and `RAN_MAX_AUTH_RETRIES` is `3`
- **THEN** the trap accepts up to 3 attempts, then answers with an error packet and disconnects

#### Scenario: Unlimited
- **WHEN** `RAN_POSTGRES_MAX_AUTH_RETRIES=0`
- **THEN** attempts continue until the session timeout

#### Scenario: Client stops answering
- **WHEN** a client disconnects after 1 of 3 allowed attempts
- **THEN** the session ends as `completed` with 1 auth attempt logged

#### Scenario: Repeated password
- **WHEN** a client answers a second password request with the same password as before
- **THEN** only one credential is logged and the session ends

#### Scenario: mysql client without CLIENT_PLUGIN_AUTH
- **WHEN** the handshake response lacks `CLIENT_PLUGIN_AUTH`
- **THEN** the trap answers ERR 1045 without an authentication switch

#### Scenario: Auth delay near the deadline
- **WHEN** the escalated auth delay would end after the session deadline
- **THEN** the delay ends at the deadline and the session outcome is `timeout`

### Requirement: RDP stays a single attempt
`rdp` SHALL NOT honor `RAN_MAX_AUTH_RETRIES` or `RAN_AUTH_DELAY`. The only user name of an RDP connection is the X.224 cookie and the negotiation failure that answers it ends the exchange, so a retry loop would be fake.

#### Scenario: Second connection request on the same socket
- **WHEN** an rdp client sends a second connection request after the negotiation failure
- **THEN** the connection is closed and exactly one credential was captured

### Requirement: Auth method meta for ssh
Every `ssh` auth attempt SHALL carry a `method` log attribute and alert meta key: `password`, `publickey` or `keyboard-interactive`.

#### Scenario: Password attempt
- **WHEN** an ssh client tries a password
- **THEN** the alert meta contains `method=password` and no password

