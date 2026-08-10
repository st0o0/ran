## MODIFIED Requirements

### Requirement: Trap startup registration
The system SHALL start all traps listed in `EnabledTraps()` by looking up their factory function in a registry map. Each trap SHALL be started in its own goroutine.

#### Scenario: Registry-based startup
- **WHEN** `EnabledTraps()` returns `["ssh", "ftp", "redis"]`
- **THEN** the system SHALL look up factory functions for ssh, ftp, and redis in the trap registry, create each trap, and start them in separate goroutines

#### Scenario: Unknown trap in EnabledTraps
- **WHEN** `EnabledTraps()` returns a name not in the registry
- **THEN** the system SHALL return an error before starting any traps
