## MODIFIED Requirements

### Requirement: Environment variable configuration
The config SHALL include CrowdSec env vars: `RAN_CROWDSEC` (on/off, default off), `RAN_CROWDSEC_URL` (required when enabled), `RAN_CROWDSEC_API_KEY` (required when enabled), `RAN_CROWDSEC_BAN_DURATION` (Go duration or `0` for permanent, default `4h`).

#### Scenario: CrowdSec enabled with all vars
- **WHEN** `RAN_CROWDSEC=on`, `RAN_CROWDSEC_URL=http://crowdsec:8080`, `RAN_CROWDSEC_API_KEY=abc123`
- **THEN** config loads successfully with CrowdSec enabled

#### Scenario: CrowdSec enabled without URL
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_URL` is not set
- **THEN** config loading returns an error

#### Scenario: CrowdSec enabled without API key
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_API_KEY` is not set
- **THEN** config loading returns an error

#### Scenario: Permanent ban duration
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=0`
- **THEN** `config.CrowdSecBanDuration` is 0 (interpreted as permanent)

#### Scenario: Custom ban duration
- **WHEN** `RAN_CROWDSEC_BAN_DURATION=24h`
- **THEN** `config.CrowdSecBanDuration` is 24 hours
