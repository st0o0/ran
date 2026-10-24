## ADDED Requirements

### Requirement: Seeded banner profiles
With `RAN_FINGERPRINT=seeded` the traps SHALL select version strings from built-in sets using a seed that is generated once and persisted, so the same instance presents the same banners after a restart.

#### Scenario: Restart
- **WHEN** the instance restarts with the same data volume
- **THEN** the SSH, MySQL and HTTP banners are unchanged

#### Scenario: Read-only data directory
- **WHEN** the seed cannot be persisted
- **THEN** an ephemeral seed is used and a warning is logged

### Requirement: Fixed mode
With `RAN_FINGERPRINT=fixed` the traps SHALL use the current fixed banner values.

#### Scenario: Fixed
- **WHEN** `RAN_FINGERPRINT=fixed`
- **THEN** the SSH banner is `SSH-2.0-OpenSSH_9.6`

### Requirement: Per-trap class meta
Single-request traps without class meta (starting with `vnc`) SHALL add a fixed `kind` key to the alert meta describing what was seen.

#### Scenario: VNC challenge response
- **WHEN** a VNC client completes the authentication exchange
- **THEN** the alert meta contains `kind=auth_response`
