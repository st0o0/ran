## ADDED Requirements

### Requirement: Ban escalation documentation in README
The README SHALL contain a "Ban Escalation" subsection under the existing "CrowdSec" section that documents how to configure CrowdSec Profiles for progressive ban duration escalation.

#### Scenario: User reads CrowdSec section
- **WHEN** a user reads the CrowdSec configuration section in README.md
- **THEN** they find a "Ban Escalation" subsection explaining that CrowdSec Profiles can override ran's default ban duration with dynamic escalation

### Requirement: Escalation profile example
The documentation SHALL include a ready-to-use CrowdSec Profile YAML example that uses `duration_expr` with `GetDecisionsCount()` to exponentially increase ban duration on repeat offenses.

#### Scenario: Exponential escalation profile
- **WHEN** a user copies the escalation profile example into their `profiles.yaml`
- **THEN** the profile filters on `Alert.Scenario startsWith 'custom/ran-'`
- **AND** uses `duration_expr` with the formula `Sprintf('%dh', 4 * (3 ^ GetDecisionsCount(Alert.GetValue())))` to escalate ban duration
- **AND** uses `on_success: break` to stop profile evaluation

#### Scenario: First-time offender with escalation profile
- **WHEN** an IP triggers a ran alert for the first time and the escalation profile is active
- **THEN** `GetDecisionsCount()` returns 0 and the ban duration is 4h

#### Scenario: Repeat offender with escalation profile
- **WHEN** an IP triggers a ran alert for the third time and the escalation profile is active
- **THEN** `GetDecisionsCount()` returns 2 and the ban duration is 36h

### Requirement: Permanent ban threshold profile example
The documentation SHALL include a CrowdSec Profile YAML example that permanently bans IPs exceeding a configurable hit threshold.

#### Scenario: Permanent ban profile
- **WHEN** a user copies the permanent ban profile example into their `profiles.yaml` above the escalation profile
- **THEN** the profile filters on `Alert.Scenario startsWith 'custom/ran-'` AND `GetDecisionsCount(Alert.GetValue()) >= 5`
- **AND** sets a ban duration of `8760h` (1 year)
- **AND** uses `on_success: break` to prevent the escalation profile from also firing

#### Scenario: IP below permanent threshold
- **WHEN** an IP has fewer than 5 prior decisions and triggers a ran alert
- **THEN** the permanent ban profile does not match and the escalation profile handles it

#### Scenario: IP at permanent threshold
- **WHEN** an IP has 5 or more prior decisions and triggers a ran alert
- **THEN** the permanent ban profile matches and the IP is banned for 8760h

### Requirement: Profile ordering guidance
The documentation SHALL explain that CrowdSec evaluates profiles top-to-bottom and that the permanent ban profile MUST be placed above the escalation profile in `profiles.yaml`.

#### Scenario: Correct profile order documented
- **WHEN** a user reads the ban escalation documentation
- **THEN** they find an explicit note that the permanent ban profile must come before the escalation profile
- **AND** the combined YAML example shows both profiles in the correct order

### Requirement: Verification command
The documentation SHALL include a `cscli` command that users can run to verify ban escalation is working correctly.

#### Scenario: User verifies escalation
- **WHEN** a user wants to confirm that escalation profiles are active
- **THEN** the documentation provides `cscli decisions list -o json` as a verification command to inspect decision durations for repeat offenders

### Requirement: Decision retention note
The documentation SHALL note that `GetDecisionsCount()` depends on CrowdSec's decision database retention and that expired/purged decisions reset the counter.

#### Scenario: User reads retention warning
- **WHEN** a user reads the ban escalation documentation
- **THEN** they find a note explaining that CrowdSec's `db_config.flush.max_age` setting affects how long decision history is retained
- **AND** the note recommends checking retention settings when using escalation

### Requirement: Default decision as fallback explanation
The documentation SHALL explain that ran's embedded default decision (`RAN_CROWDSEC_BAN_DURATION`) serves as a fallback when no CrowdSec Profile is configured, and that Profiles override this duration when they match.

#### Scenario: Fallback behavior documented
- **WHEN** a user reads the ban escalation documentation
- **THEN** they find an explanation that without Profiles, ran's default 4h ban applies unchanged
- **AND** they understand that configuring a Profile overrides ran's embedded decision duration

### Requirement: CrowdSec version prerequisite
The documentation SHALL state that `duration_expr` in Profiles requires CrowdSec >= 1.4.

#### Scenario: Version requirement documented
- **WHEN** a user reads the ban escalation documentation
- **THEN** they find a note that `duration_expr` requires CrowdSec version 1.4 or later
