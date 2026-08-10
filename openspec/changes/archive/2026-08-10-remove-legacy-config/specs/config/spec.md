## ADDED Requirements

### Requirement: SSH host key path configuration
The config SHALL load `RAN_SSH_HOST_KEY_PATH` as a string field `SSHHostKeyPath` with default value `/data/ssh_host_key`.

#### Scenario: Default SSH host key path
- **WHEN** `RAN_SSH_HOST_KEY_PATH` is not set
- **THEN** `config.SSHHostKeyPath` SHALL be `/data/ssh_host_key`

#### Scenario: Custom SSH host key path
- **WHEN** `RAN_SSH_HOST_KEY_PATH=/etc/ran/host_key` is set
- **THEN** `config.SSHHostKeyPath` SHALL be `/etc/ran/host_key`

## MODIFIED Requirements

### Requirement: Feature toggles
Traps SHALL be enabled exclusively via the `RAN_TRAPS` comma-separated list. Legacy per-trap toggle variables (`RAN_SSH`, `RAN_HTTP`, `RAN_MYSQL`) SHALL NOT be recognized.

#### Scenario: Enable traps via RAN_TRAPS
- **WHEN** `RAN_TRAPS=ssh,http,mysql` is set
- **THEN** all three traps are enabled

#### Scenario: Legacy toggle variable ignored
- **WHEN** `RAN_SSH=on` is set but `RAN_TRAPS` is not set
- **THEN** config loading SHALL return an error "at least one trap must be enabled"

### Requirement: Trap enabling validation
The system SHALL validate that at least one trap is enabled. If `RAN_TRAPS` is not set or empty, the system SHALL return an error.

#### Scenario: No traps enabled
- **WHEN** `RAN_TRAPS` is not set
- **THEN** the system SHALL return an error "at least one trap must be enabled"

#### Scenario: RAN_TRAPS enables traps
- **WHEN** `RAN_TRAPS=ftp,redis` is set
- **THEN** the system SHALL start the FTP and Redis traps

### Requirement: Address configuration
Each trap SHALL have a configurable listen address via `RAN_<PROTO>_ADDR` with defaults from `DefaultPorts`. The `TrapAddr(name)` method SHALL be the sole way to resolve a trap's listen address. Legacy dedicated address fields (`SSHAddr`, `HTTPAddr`, `MySQLAddr`) SHALL NOT exist on Config.

#### Scenario: Custom SSH port
- **WHEN** `RAN_SSH_ADDR=:2200` is set
- **THEN** `cfg.TrapAddr("ssh")` returns `:2200`

#### Scenario: Default SSH port
- **WHEN** `RAN_SSH_ADDR` is not set and ssh trap is enabled
- **THEN** `cfg.TrapAddr("ssh")` returns `:2222`

## REMOVED Requirements

### Requirement: Legacy per-trap boolean fields
**Reason**: Replaced by generic `Traps []string` system. The `SSH`, `HTTP`, `MySQL` boolean fields on Config are removed.
**Migration**: Check trap membership via `EnabledTraps()` or the `Traps` slice.

### Requirement: Legacy per-trap address fields
**Reason**: Replaced by `Addrs map[string]string` and `TrapAddr()`. The `SSHAddr`, `HTTPAddr`, `MySQLAddr` fields on Config are removed.
**Migration**: Use `cfg.TrapAddr("ssh")`, `cfg.TrapAddr("http")`, `cfg.TrapAddr("mysql")`.
