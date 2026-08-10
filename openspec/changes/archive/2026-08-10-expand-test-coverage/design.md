## Context

RAN has 27 trap implementations, each with its own `_test.go`. However, shared infrastructure in `internal/trap/trap.go` (`ParseAddr`, `NewSession`, `deadlineFromContext`), `internal/metrics/metrics.go` (`New`), and `cmd/ran/run.go` (`run`) have zero test coverage. The integration test in `internal/trap/integration_test.go` only exercises SSH, HTTP, and MySQL.

## Goals / Non-Goals

**Goals:**
- Unit-test all exported and key unexported helpers in `internal/trap/trap.go`
- Unit-test metric registration in `internal/metrics`
- Unit-test the `run()` orchestrator for success, partial-failure, and total-failure paths
- Extend integration test to cover FTP, Telnet, and Redis traps at minimum

**Non-Goals:**
- Refactoring production code for testability (tests adapt to current interfaces)
- Achieving 100% line coverage across the entire codebase
- Adding benchmarks or fuzz tests
- Testing traps beyond FTP/Telnet/Redis in this change (others can follow later)

## Decisions

**1. Test `run()` using real registry factories, not mocks**
Rationale: The `run()` function iterates `Registry` entries and calls factories. Using real (or minimal stub) factories avoids coupling tests to mock interfaces that don't exist yet. Tests will use `t.TempDir()` and ephemeral ports to avoid conflicts.
Alternative considered: Injecting a mock registry -- rejected because it would require refactoring `run.go` to accept a registry parameter, which is out of scope.

**2. Integration tests use the same dial-and-expect pattern as existing SSH/HTTP/MySQL tests**
Rationale: Consistency with the existing `TestIntegrationAllTraps` structure. FTP, Telnet, and Redis are TCP-based and respond to simple connect/command sequences, making them straightforward to validate.

**3. Place `trap_test.go` alongside `trap.go` in `internal/trap/`**
Rationale: Standard Go convention. Uses `package trap` (not `trap_test`) to access unexported `deadlineFromContext`.

## Risks / Trade-offs

- [Port conflicts in CI] -> Use `127.0.0.1:0` or high ephemeral ports; mark integration tests with build tag or `testing.Short()` guard.
- [Flaky integration tests from timing] -> Use generous dial timeouts and retry loops matching existing test patterns.
- [Testing `run()` without mocks ties tests to real trap startup] -> Accept this: the goal is to test orchestration with real components; isolate with unique ports per test.
