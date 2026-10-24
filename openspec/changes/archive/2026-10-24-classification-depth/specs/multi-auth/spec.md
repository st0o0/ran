## ADDED Requirements

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
