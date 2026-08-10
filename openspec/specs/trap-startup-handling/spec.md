# trap-startup-handling Specification

## Purpose
TBD - created by archiving change fix-trap-startup-errors. Update Purpose after archive.
## Requirements
### Requirement: Drain startup errors
The orchestrator SHALL read one result from `errc` for each launched trap goroutine after all goroutines have been spawned.

#### Scenario: All traps start successfully
- **WHEN** every trap's `Start()` returns nil
- **THEN** `run()` proceeds to block on `ctx.Done()`

#### Scenario: Channel fully drained
- **WHEN** N traps are launched
- **THEN** exactly N reads from `errc` are performed before proceeding

### Requirement: Log individual startup failures
The orchestrator SHALL log each non-nil trap startup error at `slog.Error` level, including the trap name.

#### Scenario: One trap fails to start
- **WHEN** one trap returns a non-nil error from `Start()`
- **THEN** the error is logged at Error level with the trap's name
- **AND** remaining healthy traps continue running

#### Scenario: Multiple traps fail to start
- **WHEN** several traps return non-nil errors
- **THEN** each failure is logged individually at Error level

### Requirement: Fail-fast on total failure
The orchestrator SHALL cancel the context and return an error when ALL traps fail to start.

#### Scenario: All traps fail
- **WHEN** every trap's `Start()` returns a non-nil error
- **THEN** `run()` cancels the context and returns an error describing total failure

#### Scenario: At least one trap succeeds
- **WHEN** at least one trap starts successfully and others fail
- **THEN** `run()` blocks on `ctx.Done()` and does NOT return an error

### Requirement: Start must return promptly
Each trap's `Start()` method SHALL return (nil or error) after initiating its listener, not block for the lifetime of the trap.

#### Scenario: Trap binds and returns
- **WHEN** a trap successfully binds its port
- **THEN** `Start()` returns nil without blocking on incoming connections

