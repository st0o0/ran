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
For each new trap, the system SHALL accept a `RAN_<PROTO>_ADDR` environment variable to override the default listen address.

#### Scenario: All new traps have default addresses
- **WHEN** a trap is enabled without a corresponding `RAN_<PROTO>_ADDR`
- **THEN** the trap SHALL listen on its default port (FTP=:21, Telnet=:23, SMTP=:25, DNS=:53, POP3=:110, IMAP=:143, LDAP=:389, SMB=:445, Modbus=:502, SOCKS5=:1080, MSSQL=:1433, Oracle=:1521, MQTT=:1883, RDP=:3389, PostgreSQL=:5432, SIP=:5060, VNC=:5900, Redis=:6379, IRC=:6667, HTTP Proxy=:8080, Elasticsearch=:9200, Memcached=:11211, NTP=:123, SNMP=:161)
