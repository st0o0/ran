## MODIFIED Requirements

### Requirement: Healthcheck subcommand
`ran healthcheck` SHALL perform an HTTP GET request to `http://<metricsAddr>/healthz` with a 2-second timeout. When `metricsAddr` has no explicit host (e.g. `:9550`), the subcommand SHALL use `localhost` as the host. It SHALL exit 0 on HTTP 200, exit 1 on any error (connection refused, timeout, non-200 status).

#### Scenario: Healthy process
- **WHEN** `ran healthcheck` is run while the metrics server is listening and `/healthz` returns HTTP 200
- **THEN** it exits with code 0

#### Scenario: Unhealthy process
- **WHEN** `ran healthcheck` is run but the metrics server is not reachable
- **THEN** it prints "ran: unhealthy" to stderr and exits with code 1

#### Scenario: Non-200 response
- **WHEN** `ran healthcheck` is run and `/healthz` returns a non-200 status code
- **THEN** it prints "ran: unhealthy" to stderr and exits with code 1
