## ADDED Requirements

### Requirement: Multi-auth retries configuration
`RAN_MAX_AUTH_RETRIES` (default `3`) SHALL set the global maximum auth attempts per session. `RAN_<PROTO>_MAX_AUTH_RETRIES` SHALL override the global value for a specific protocol. A value of `0` SHALL mean unlimited (bounded by session timeout). The Config struct SHALL expose a `ResolveMaxAuthRetries(proto string) int` method that checks the per-protocol override first, then falls back to the global value.

#### Scenario: Global default
- **WHEN** `RAN_MAX_AUTH_RETRIES` is not set
- **THEN** `ResolveMaxAuthRetries("telnet")` SHALL return `3`

#### Scenario: Global override
- **WHEN** `RAN_MAX_AUTH_RETRIES=5` is set
- **THEN** `ResolveMaxAuthRetries("telnet")` SHALL return `5`

#### Scenario: Per-protocol override
- **WHEN** `RAN_MAX_AUTH_RETRIES=3` and `RAN_SSH_MAX_AUTH_RETRIES=6` are set
- **THEN** `ResolveMaxAuthRetries("ssh")` SHALL return `6` and `ResolveMaxAuthRetries("telnet")` SHALL return `3`

#### Scenario: Unlimited
- **WHEN** `RAN_MSSQL_MAX_AUTH_RETRIES=0` is set
- **THEN** `ResolveMaxAuthRetries("mssql")` SHALL return `0`

#### Scenario: Invalid value
- **WHEN** `RAN_MAX_AUTH_RETRIES=banana` is set
- **THEN** config loading SHALL return an error

### Requirement: Auth delay configuration
`RAN_AUTH_DELAY` (default `0s`) SHALL set the global base auth delay. `RAN_<PROTO>_AUTH_DELAY` SHALL override the global value for a specific protocol. The Config struct SHALL expose a `ResolveAuthDelay(proto string) time.Duration` method.

#### Scenario: Delay disabled by default
- **WHEN** `RAN_AUTH_DELAY` is not set
- **THEN** `ResolveAuthDelay("ssh")` SHALL return `0s`

#### Scenario: Per-protocol delay
- **WHEN** `RAN_AUTH_DELAY=1s` and `RAN_SSH_AUTH_DELAY=3s` are set
- **THEN** `ResolveAuthDelay("ssh")` SHALL return `3s` and `ResolveAuthDelay("telnet")` SHALL return `1s`

#### Scenario: Invalid duration
- **WHEN** `RAN_AUTH_DELAY=notaduration` is set
- **THEN** config loading SHALL return an error

### Requirement: SSH tarpit configuration
`RAN_SSH_TARPIT` (on/off, default off) SHALL enable the SSH pre-auth tarpit. `RAN_SSH_TARPIT_DURATION` (Go duration, default `30s`) SHALL set the tarpit phase duration.

#### Scenario: Tarpit disabled
- **WHEN** `RAN_SSH_TARPIT` is not set
- **THEN** `Config.SSHTarpit` SHALL be `false`

#### Scenario: Tarpit enabled with custom duration
- **WHEN** `RAN_SSH_TARPIT=on` and `RAN_SSH_TARPIT_DURATION=1m` are set
- **THEN** `Config.SSHTarpit` SHALL be `true` and `Config.SSHTarpitDuration` SHALL be `60s`

#### Scenario: Tarpit enabled with default duration
- **WHEN** `RAN_SSH_TARPIT=on` is set without `RAN_SSH_TARPIT_DURATION`
- **THEN** `Config.SSHTarpitDuration` SHALL be `30s`

### Requirement: Per-protocol session timeout
`RAN_<PROTO>_SESSION_TIMEOUT` SHALL override the global `RAN_SESSION_TIMEOUT` for a specific protocol. The Config struct SHALL expose a `ResolveSessionTimeout(proto string) time.Duration` method.

#### Scenario: Global timeout applies
- **WHEN** `RAN_SESSION_TIMEOUT=30s` is set and no per-protocol override exists
- **THEN** `ResolveSessionTimeout("ssh")` SHALL return `30s`

#### Scenario: Per-protocol timeout
- **WHEN** `RAN_SESSION_TIMEOUT=30s` and `RAN_SSH_SESSION_TIMEOUT=120s` are set
- **THEN** `ResolveSessionTimeout("ssh")` SHALL return `120s` and `ResolveSessionTimeout("telnet")` SHALL return `30s`

#### Scenario: Invalid per-protocol timeout
- **WHEN** `RAN_SSH_SESSION_TIMEOUT=notvalid` is set
- **THEN** config loading SHALL return an error
