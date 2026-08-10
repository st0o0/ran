## MODIFIED Requirements

### Requirement: CrowdSec alert counter
`ran_crowdsec_alerts_total{protocol,status}` SHALL be a counter tracking alert push results. Status labels: `success`, `failure`.

#### Scenario: Successful alert
- **WHEN** a CrowdSec alert is pushed successfully
- **THEN** `ran_crowdsec_alerts_total{protocol="ssh",status="success"}` is incremented

#### Scenario: Failed alert
- **WHEN** a CrowdSec alert push fails
- **THEN** `ran_crowdsec_alerts_total{protocol="ssh",status="failure"}` is incremented
