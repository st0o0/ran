## Purpose

Configuration system for enabling and managing honeypot traps via environment variables, supporting both a unified trap list and legacy per-trap variables.

## Requirements

### Requirement: RAN_TRAPS list configuration
The system SHALL support a `RAN_TRAPS` environment variable containing a comma-separated list of trap names to enable (e.g., `RAN_TRAPS=ssh,ftp,telnet,redis`).

#### Scenario: Enable traps via list
- **WHEN** `RAN_TRAPS=ssh,ftp,redis` is set
- **THEN** only the SSH, FTP, and Redis traps SHALL be started

#### Scenario: Unknown trap name in list
- **WHEN** `RAN_TRAPS` contains an unrecognized trap name
- **THEN** the system SHALL return a configuration error listing the unknown name and all valid trap names

### Requirement: Legacy per-trap env vars
The system SHALL continue to support `RAN_SSH=on`, `RAN_HTTP=on`, `RAN_MYSQL=on` for backwards compatibility. If both `RAN_TRAPS` and legacy vars are set, `RAN_TRAPS` takes precedence.

#### Scenario: Legacy env var still works
- **WHEN** `RAN_SSH=on` is set and `RAN_TRAPS` is not set
- **THEN** the SSH trap SHALL be enabled

#### Scenario: RAN_TRAPS overrides legacy
- **WHEN** `RAN_TRAPS=ftp` and `RAN_SSH=on` are both set
- **THEN** only the FTP trap SHALL be enabled

### Requirement: Default port mapping
Each trap SHALL have a default listen address. Users MAY override via `RAN_<PROTO>_ADDR` (e.g., `RAN_FTP_ADDR=:2121`).

#### Scenario: Default port used
- **WHEN** FTP trap is enabled and `RAN_FTP_ADDR` is not set
- **THEN** the FTP trap SHALL listen on `:21`

#### Scenario: Custom port override
- **WHEN** `RAN_FTP_ADDR=:2121` is set
- **THEN** the FTP trap SHALL listen on `:2121`

### Requirement: EnabledTraps method
Config SHALL expose an `EnabledTraps() []string` method returning the list of trap names to start, resolved from either `RAN_TRAPS` or legacy env vars.

#### Scenario: EnabledTraps returns correct list
- **WHEN** `RAN_TRAPS=ssh,ftp,redis` is configured
- **THEN** `EnabledTraps()` SHALL return `["ssh", "ftp", "redis"]`
