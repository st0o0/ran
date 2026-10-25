# crowdsec-integration-test Specification

## Purpose
TBD - created by archiving change crowdsec-integration. Update Purpose after archive.
## Requirements
### Requirement: Profile behavior is tested against a real CrowdSec
CI SHALL run rán's alert sink against a pinned `crowdsecurity/crowdsec` LAPI with the embedded profile and SHALL fail when escalation, class filtering or allowlist handling differ from the documented behavior.

#### Scenario: Escalation
- **WHEN** two `attack` alerts for the same IP are pushed one after the other
- **THEN** the first decision lasts about 1h and the second about 3h

#### Scenario: Probe
- **WHEN** a `probe` alert is pushed
- **THEN** no decision exists for that IP

#### Scenario: Allowlisted source
- **WHEN** an alert for an allowlisted IP is pushed
- **THEN** no decision exists for that IP

### Requirement: Host without Docker
The integration test SHALL skip when `RAN_CROWDSEC_IT` is unset, so `go test ./...` does not need Docker.

#### Scenario: Default test run
- **WHEN** `go test ./...` runs without `RAN_CROWDSEC_IT`
- **THEN** the integration test is not compiled or is skipped, and the run passes

