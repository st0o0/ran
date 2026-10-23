# credential-logging Specification

## Purpose
TBD - created by archiving change security-hotfix. Update Purpose after archive.
## Requirements
### Requirement: Password logging mode
`RAN_LOG_PASSWORDS` SHALL accept `off`, `mask` and `on`, default `off`. With `off` the `password` field SHALL be omitted from credential log events; with `mask` it SHALL be `***` plus the length; with `on` the cleartext value SHALL be logged. Invalid values SHALL fail config loading.

#### Scenario: Default
- **WHEN** `RAN_LOG_PASSWORDS` is unset and credentials are captured
- **THEN** the log event contains `username` and no `password`

#### Scenario: Mask
- **WHEN** `RAN_LOG_PASSWORDS=mask` and the password is `hunter2`
- **THEN** the log field is `*** (7)`

#### Scenario: On
- **WHEN** `RAN_LOG_PASSWORDS=on`
- **THEN** the cleartext password is logged

### Requirement: Passwords never leave the host via CrowdSec
Cleartext passwords SHALL NOT be included in CrowdSec event meta regardless of `RAN_LOG_PASSWORDS`.

#### Scenario: Mode on
- **WHEN** `RAN_LOG_PASSWORDS=on` and an alert is pushed
- **THEN** the LAPI payload has no `password` meta key

