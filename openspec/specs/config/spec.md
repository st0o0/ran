## Purpose

Environment-variable-based configuration loading for the ran honeypot, controlling trap toggles, listen addresses, timeouts, connection limits, logging, and metrics.

## Requirements

### Requirement: Environment variable configuration
The config SHALL be loaded exclusively from environment variables with the `RAN_` prefix. The loader SHALL accept a `getenv func(string) string` parameter for testability.

#### Scenario: All defaults
- **WHEN** no `RAN_*` environment variables are set
- **THEN** config loads with defaults: all traps off, log level info, log format json, metrics addr `:9550`, session timeout 30s, max sessions 500, max per IP 10

#### Scenario: Testable without real env vars
- **WHEN** `Load(func(string) string)` is called with a custom getenv function
- **THEN** config reads values from the provided function, not `os.Getenv`

### Requirement: Feature toggles
Trap features SHALL be toggled via `on`/`off` string values: `RAN_SSH`, `RAN_HTTP`, `RAN_MYSQL`.

#### Scenario: Enable SSH trap
- **WHEN** `RAN_SSH=on` is set
- **THEN** `config.SSH` is true

#### Scenario: Invalid toggle value
- **WHEN** `RAN_SSH=yes` is set (not `on` or `off`)
- **THEN** config loading returns an error

### Requirement: Address configuration
Each trap SHALL have a configurable listen address: `RAN_SSH_ADDR` (default `:2222`), `RAN_HTTP_ADDR` (default `:8081`), `RAN_MYSQL_ADDR` (default `:3307`).

#### Scenario: Custom SSH port
- **WHEN** `RAN_SSH_ADDR=:2200` is set
- **THEN** the SSH trap listens on port 2200

### Requirement: Duration parsing
Duration fields SHALL use Go `time.ParseDuration` format (e.g. `30s`, `1m`). Affected: `RAN_SESSION_TIMEOUT` (default `30s`).

#### Scenario: Custom timeout
- **WHEN** `RAN_SESSION_TIMEOUT=1m` is set
- **THEN** session timeout is 60 seconds

#### Scenario: Invalid duration
- **WHEN** `RAN_SESSION_TIMEOUT=banana` is set
- **THEN** config loading returns an error

### Requirement: Log configuration
`RAN_LOG_LEVEL` SHALL support `debug`, `info`, `warn`, `error` (default `info`). `RAN_LOG_FORMAT` SHALL support `text`, `json` (default `json`).

#### Scenario: Debug logging
- **WHEN** `RAN_LOG_LEVEL=debug` is set
- **THEN** slog level is set to `slog.LevelDebug`

### Requirement: Connection limits
`RAN_MAX_SESSIONS` (default `500`) SHALL set the global concurrent session limit. `RAN_MAX_PER_IP` (default `10`) SHALL set the per-IP concurrent session limit.

#### Scenario: Custom limits
- **WHEN** `RAN_MAX_SESSIONS=200` and `RAN_MAX_PER_IP=5` are set
- **THEN** config reflects these values

### Requirement: Metrics address
`RAN_METRICS_ADDR` (default `:9550`) SHALL configure the Prometheus metrics HTTP server listen address.

#### Scenario: Custom metrics port
- **WHEN** `RAN_METRICS_ADDR=:9999` is set
- **THEN** the metrics server listens on port 9999

### Requirement: CrowdSec configuration
The config SHALL include CrowdSec env vars: `RAN_CROWDSEC` (on/off, default off), `RAN_CROWDSEC_URL` (required when enabled), `RAN_CROWDSEC_MACHINE_ID` (required when enabled), `RAN_CROWDSEC_PASSWORD` (required when enabled), `RAN_CROWDSEC_BAN_DURATION` (Go duration or `0` for permanent, default `4h`).

#### Scenario: CrowdSec enabled with all vars
- **WHEN** `RAN_CROWDSEC=on`, `RAN_CROWDSEC_URL=http://crowdsec:8080`, `RAN_CROWDSEC_MACHINE_ID=ran-honeypot`, `RAN_CROWDSEC_PASSWORD=secret`
- **THEN** config loads successfully with CrowdSec enabled

#### Scenario: CrowdSec enabled without machine ID
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_MACHINE_ID` is not set
- **THEN** config loading returns an error

#### Scenario: CrowdSec enabled without password
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_PASSWORD` is not set
- **THEN** config loading returns an error

#### Scenario: CrowdSec enabled without URL
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_URL` is not set
- **THEN** config loading returns an error

#### Scenario: Permanent ban duration
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=0`
- **THEN** `config.CrowdSecBanDuration` is 0 (interpreted as permanent)

#### Scenario: Custom ban duration
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=24h`
- **THEN** `config.CrowdSecBanDuration` is 24 hours

### Requirement: Trap enabling validation
The system SHALL validate that at least one trap is enabled. If neither `RAN_TRAPS` nor any legacy `RAN_<PROTO>=on` variable is set, the system SHALL return an error.

#### Scenario: No traps enabled
- **WHEN** neither `RAN_TRAPS` nor any `RAN_SSH`/`RAN_HTTP`/`RAN_MYSQL` variable is set
- **THEN** the system SHALL return an error "at least one trap must be enabled"

#### Scenario: RAN_TRAPS enables traps
- **WHEN** `RAN_TRAPS=ftp,redis` is set
- **THEN** the system SHALL start the FTP and Redis traps

### Requirement: Per-trap address configuration
For each trap, the system SHALL accept a `RAN_<PROTO>_ADDR` environment variable to override the default listen address. The value MAY contain multiple comma-separated addresses (e.g. `:8081,:8080,:8443`). The system SHALL store the raw value in `Config.Addrs[name]`. A new `TrapAddrs(name) []string` method SHALL split the stored value on commas, trim whitespace from each segment, and return the list. `TrapAddr(name) string` SHALL continue to return the raw stored string for backward compatibility.

#### Scenario: Single address (backward compatible)
- **WHEN** `RAN_SSH_ADDR=:2200` is set
- **THEN** `TrapAddr("ssh")` returns `:2200` and `TrapAddrs("ssh")` returns `[":2200"]`

#### Scenario: Multiple addresses
- **WHEN** `RAN_HTTP_ADDR=:8081,:8080,:8443` is set
- **THEN** `TrapAddr("http")` returns `:8081,:8080,:8443` and `TrapAddrs("http")` returns `[":8081", ":8080", ":8443"]`

#### Scenario: Whitespace in comma-separated list
- **WHEN** `RAN_HTTP_ADDR=:8081, :8080 , :8443` is set
- **THEN** `TrapAddrs("http")` returns `[":8081", ":8080", ":8443"]` with whitespace trimmed

#### Scenario: All new traps have default addresses
- **WHEN** a trap is enabled without a corresponding `RAN_<PROTO>_ADDR`
- **THEN** the trap SHALL listen on its default port (FTP=:21, Telnet=:23, SMTP=:25, DNS=:53, POP3=:110, IMAP=:143, LDAP=:389, SMB=:445, Modbus=:502, SOCKS5=:1080, MSSQL=:1433, Oracle=:1521, MQTT=:1883, RDP=:3389, PostgreSQL=:5432, SIP=:5060, VNC=:5900, Redis=:6379, IRC=:6667, HTTP Proxy=:8080, Elasticsearch=:9200, Memcached=:11211, NTP=:123, SNMP=:161, ADB=:5555, Minecraft=:25565)

### Requirement: ADB and Minecraft in DefaultPorts and ValidTraps
The `DefaultPorts` map SHALL include entries for `adb` (`:5555`) and `minecraft` (`:25565`). The `ValidTraps` set SHALL include `adb` and `minecraft` as valid trap names for `RAN_TRAPS`.

#### Scenario: Enable ADB trap
- **WHEN** `RAN_TRAPS=adb` is set
- **THEN** the system SHALL start the ADB trap on its default port :5555

#### Scenario: Enable Minecraft trap
- **WHEN** `RAN_TRAPS=minecraft` is set
- **THEN** the system SHALL start the Minecraft trap on its default port :25565

#### Scenario: Unknown trap rejected
- **WHEN** `RAN_TRAPS=unknowntrap` is set
- **THEN** config loading returns an error listing valid trap names including `adb` and `minecraft`

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
