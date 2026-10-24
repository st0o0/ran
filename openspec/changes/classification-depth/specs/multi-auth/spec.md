## ADDED Requirements

### Requirement: Retries for mysql, postgres and rdp
`mysql`, `postgres` and `rdp` SHALL honor `RAN_MAX_AUTH_RETRIES` and `RAN_AUTH_DELAY` (and their per-trap overrides) like `ssh`, `telnet`, `mssql` and `smb`. `0` SHALL mean unlimited attempts until the session timeout.

#### Scenario: Default retries
- **WHEN** a mysql client fails authentication and `RAN_MAX_AUTH_RETRIES` is `3`
- **THEN** the trap accepts up to 3 attempts, then disconnects

#### Scenario: Unlimited
- **WHEN** `RAN_POSTGRES_MAX_AUTH_RETRIES=0`
- **THEN** attempts continue until the session timeout
