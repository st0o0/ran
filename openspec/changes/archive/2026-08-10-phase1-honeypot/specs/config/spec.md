## ADDED Requirements

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

### Requirement: Validation
Config loading SHALL fail with a descriptive error if no traps are enabled.

#### Scenario: No traps enabled
- **WHEN** all trap toggles are off (or unset)
- **THEN** config loading returns an error indicating at least one trap must be enabled
