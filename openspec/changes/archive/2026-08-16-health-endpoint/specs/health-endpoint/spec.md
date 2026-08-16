## ADDED Requirements

### Requirement: Health endpoint
The metrics HTTP server SHALL serve a `GET /healthz` endpoint that returns a JSON object with the fields `status`, `version`, `uptime`, and `traps`.

#### Scenario: Healthy response
- **WHEN** `GET /healthz` is requested while the process is running
- **THEN** the response status code SHALL be 200, Content-Type SHALL be `application/json`, and the body SHALL contain `{"status":"ok","version":"<version>","uptime":"<duration>","traps":["<name>",...]}`

#### Scenario: Version field
- **WHEN** the binary was built with `-ldflags "-X main.version=1.2.3"`
- **THEN** the `version` field in the `/healthz` response SHALL be `"1.2.3"`

#### Scenario: Uptime field
- **WHEN** the process has been running for 2 hours, 15 minutes, and 3 seconds
- **THEN** the `uptime` field SHALL be `"2h15m3s"`

#### Scenario: Traps field
- **WHEN** `RAN_TRAPS=ssh,http,rdp` is configured
- **THEN** the `traps` field SHALL be `["ssh","http","rdp"]`

### Requirement: Health endpoint response encoding
The `/healthz` response SHALL be encoded as JSON with `Content-Type: application/json`. The handler SHALL NOT expose internal errors to the client.

#### Scenario: Valid JSON
- **WHEN** `GET /healthz` is requested
- **THEN** the response body SHALL be valid JSON parseable by any standard JSON parser
