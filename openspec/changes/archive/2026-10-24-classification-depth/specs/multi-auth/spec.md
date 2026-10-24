## ADDED Requirements

### Requirement: Retries for mysql and postgres
`mysql` and `postgres` SHALL honor `RAN_MAX_AUTH_RETRIES` and `RAN_AUTH_DELAY` (and their per-trap overrides) like `ssh`, `telnet`, `mssql` and `smb`. `0` SHALL mean unlimited attempts until the session timeout. `mysql` SHALL ask for each further attempt with an authentication switch to `mysql_clear_password` and take the clear text password from the reply. `postgres` SHALL repeat the cleartext password request after a rejected password, without an error in between, and send the error response only after the last attempt.

#### Scenario: Default retries
- **WHEN** a mysql client fails authentication and `RAN_MAX_AUTH_RETRIES` is `3`
- **THEN** the trap accepts up to 3 attempts, then answers with an error packet and disconnects

#### Scenario: Unlimited
- **WHEN** `RAN_POSTGRES_MAX_AUTH_RETRIES=0`
- **THEN** attempts continue until the session timeout

#### Scenario: Client stops answering
- **WHEN** a client disconnects after 1 of 3 allowed attempts
- **THEN** the session ends as `completed` with 1 auth attempt logged

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
