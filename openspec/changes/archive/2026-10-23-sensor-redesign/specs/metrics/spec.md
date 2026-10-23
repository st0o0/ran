## MODIFIED Requirements

### Requirement: CrowdSec pipeline funnel metric
`ran_crowdsec_pipeline_total{protocol, stage}` SHALL be a counter. Stage values: `received`, `filtered`, `cooldown`, `queued`, `sent`, `failed`, `dropped`. The stages `cached` and `deduplicated` SHALL no longer be emitted. All other `ran_*` metrics SHALL keep their names and labels.

#### Scenario: Full pipeline success
- **WHEN** an alert is received, passes the class filter and cooldown, is queued and pushed
- **THEN** `received`, `queued` and `sent` are each incremented

#### Scenario: Alert filtered by class
- **WHEN** a session's class is not in `RAN_BAN_ON`
- **THEN** `received` and `filtered` are incremented

#### Scenario: Alert in cooldown
- **WHEN** an alert for the same IP and class is within `RAN_ALERT_COOLDOWN`
- **THEN** `received` and `cooldown` are incremented

#### Scenario: Funnel arithmetic
- **WHEN** querying delivery rate
- **THEN** `rate(ran_crowdsec_pipeline_total{stage="sent"}[5m]) / rate(ran_crowdsec_pipeline_total{stage="queued"}[5m])` gives the delivery ratio

#### Scenario: Existing dashboards
- **WHEN** a dashboard queries `ran_connections_total{protocol}` or `ran_credentials_captured_total{protocol}`
- **THEN** it keeps working unchanged
