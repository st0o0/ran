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

### Requirement: HTTPS trap registration
The system SHALL accept `https` as a trap name in `RAN_TRAPS` with the default listen address `:8443`, overridable (also with several comma-separated addresses) through `RAN_HTTPS_ADDR`. `RAN_HTTPS_CERT_PATH` (default `/data/https_cert.pem`) SHALL name the certificate file of the trap. `config.DefaultPorts`, `config.ValidTraps` and `trap.Registry` SHALL all contain `https`.

#### Scenario: Default address
- **WHEN** `RAN_TRAPS=https` is set and `RAN_HTTPS_ADDR` is not
- **THEN** `TrapAddr("https")` returns `:8443`

#### Scenario: Certificate path
- **WHEN** `RAN_HTTPS_CERT_PATH` is not set
- **THEN** the certificate path is `/data/https_cert.pem`

### Requirement: Docker, Kubernetes and MongoDB traps
`docker`, `kubernetes` and `mongodb` SHALL be valid trap names with default ports `:2375`, `:6443` and `:27017`, registered in `DefaultPorts`, `ValidTraps` and `Registry`.

#### Scenario: Enable the new traps
- **WHEN** `RAN_TRAPS=docker,kubernetes,mongodb` is set
- **THEN** all three traps start on their default ports and appear in `/healthz`

### Requirement: Telnet default addresses
The default listen addresses of `telnet` SHALL be `:23,:2323`. Binding follows the multi-port rule: if one of the two addresses cannot be bound, the trap fails to start and releases the other one (all or nothing). `RAN_TELNET_ADDR` replaces both defaults.

#### Scenario: Default telnet
- **WHEN** `RAN_TRAPS=telnet` is set without `RAN_TELNET_ADDR`
- **THEN** the trap listens on `:23` and `:2323`

#### Scenario: One default address is taken
- **WHEN** `:2323` is already in use and `RAN_TELNET_ADDR` is not set
- **THEN** the telnet trap fails to start with a listen error and the operator sets `RAN_TELNET_ADDR=:23`

### Requirement: Catch-all and banner traps
`catchall` and `banner` SHALL be valid trap names without a default port; they are listed in `config.AddresslessTraps` together with the variable they require, and are not part of `config.DefaultPorts`. Enabling either without its address variable (`RAN_CATCHALL_ADDR`, `RAN_BANNER_SERVICES`) SHALL make the configuration invalid with a message naming the variable. The variables SHALL be read only when the trap is enabled.

#### Scenario: Missing address
- **WHEN** `RAN_TRAPS=catchall` is set without `RAN_CATCHALL_ADDR`
- **THEN** `ran check-config` exits 1 and names `RAN_CATCHALL_ADDR`

#### Scenario: Missing services
- **WHEN** `RAN_TRAPS=banner` is set without `RAN_BANNER_SERVICES`
- **THEN** `ran check-config` exits 1 and names `RAN_BANNER_SERVICES`

#### Scenario: Registry agreement
- **WHEN** the tests compare `DefaultPorts`, `AddresslessTraps`, `ValidTraps` and `trap.Registry`
- **THEN** the first two are disjoint and their union equals the other two

