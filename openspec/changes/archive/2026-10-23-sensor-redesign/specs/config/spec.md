## MODIFIED Requirements

### Requirement: CrowdSec configuration
The config SHALL include `RAN_CROWDSEC` (on/off, default off), `RAN_CROWDSEC_URL`, `RAN_CROWDSEC_MACHINE_ID` and `RAN_CROWDSEC_PASSWORD` (the last three required when enabled), `RAN_CROWDSEC_BATCH_INTERVAL` and `RAN_CROWDSEC_BATCH_SIZE` (unchanged), `RAN_BAN_ON` (comma-separated subset of `probe,attack,scan`, default `attack,scan`) and `RAN_ALERT_COOLDOWN` (Go duration, default `4h`, `0s` disables) and `RAN_PROBE_SUMMARY_WINDOW` (Go duration, default `60s`, `0s` disables aggregation). `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and `RAN_CROWDSEC_DEDUP_WINDOW` SHALL have no effect and are only checked for presence to log the warning.

#### Scenario: CrowdSec enabled with all vars
- **WHEN** `RAN_CROWDSEC=on` with URL, machine ID and password set
- **THEN** config loads successfully

#### Scenario: CrowdSec enabled without machine ID
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_MACHINE_ID` is not set
- **THEN** config loading returns an error

#### Scenario: CrowdSec enabled without password
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_PASSWORD` is not set
- **THEN** config loading returns an error

#### Scenario: CrowdSec enabled without URL
- **WHEN** `RAN_CROWDSEC=on` but `RAN_CROWDSEC_URL` is not set
- **THEN** config loading returns an error

#### Scenario: Default ban classes
- **WHEN** `RAN_BAN_ON` is not set
- **THEN** the enabled classes are `attack` and `scan`

#### Scenario: Custom ban classes
- **WHEN** `RAN_BAN_ON=probe,attack,scan`
- **THEN** all three classes are enabled

#### Scenario: Invalid class
- **WHEN** `RAN_BAN_ON=attack,foo`
- **THEN** config loading returns an error naming the invalid value

#### Scenario: Default cooldown
- **WHEN** `RAN_ALERT_COOLDOWN` is not set
- **THEN** the cooldown is 4 hours

#### Scenario: Removed variable set
- **WHEN** `RAN_CROWDSEC_BAN_DURATION` is set in the environment
- **THEN** it is ignored and a one-time startup warning is logged
