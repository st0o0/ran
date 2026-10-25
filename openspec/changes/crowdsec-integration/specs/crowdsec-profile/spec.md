## ADDED Requirements

### Requirement: Shipped example profile
The binary SHALL embed the example CrowdSec profile and `ran crowdsec-profile` SHALL print it to stdout and exit 0, without reading the configuration. The profile SHALL ban `scan` and `attack` alerts of `custom/ran-*` scenarios with the escalating duration `min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue()))` hours and SHALL stop evaluation without a decision for every other `custom/ran-*` alert.

#### Scenario: Print the profile
- **WHEN** `ran crowdsec-profile` runs
- **THEN** the output is the embedded `profiles.yaml` and the exit code is 0

#### Scenario: Probe alert
- **WHEN** an alert of class `probe` reaches the LAPI
- **THEN** no decision is created even if a generic `Remediation == true` profile follows

### Requirement: Docs use the shipped profile
The documentation SHALL include the embedded profile through a generated file, and a test SHALL fail when the generated file differs from the embedded profile.

#### Scenario: Profile edited without regenerating
- **WHEN** `profiles.yaml` changes and `docs/crowdsec-profile.generated.md` does not
- **THEN** the drift test fails
