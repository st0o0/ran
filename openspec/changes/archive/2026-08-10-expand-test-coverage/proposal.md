## Why

The project has 27 traps but test coverage gaps in core infrastructure: `ParseAddr`, `NewSession`, `deadlineFromContext`, metrics registration, and the `run()` orchestration function are untested. The integration test only exercises 3 of 27 traps (SSH, HTTP, MySQL). Expanding coverage catches regressions in shared foundations and validates more trap implementations end-to-end.

## What Changes

- Add unit tests for `internal/trap` package: `ParseAddr`, `NewSession`, `deadlineFromContext`
- Add unit tests for `internal/metrics` package: `New()` metric registration
- Add unit tests for `cmd/ran/run()`: successful startup, partial failure, total failure scenarios
- Extend `integration_test.go` to cover FTP, Telnet, and Redis traps (minimum), beyond the existing SSH/HTTP/MySQL

## Capabilities

### New Capabilities
- `test-coverage`: Unit and integration test coverage for core infrastructure and additional trap integration tests

### Modified Capabilities

_None_ -- no existing spec requirements change; this adds tests only.

## Impact

- New test files: `internal/trap/trap_test.go`, `internal/metrics/metrics_test.go`, `cmd/ran/run_test.go`
- Modified file: `integration_test.go`
- No production code changes, no API changes, no dependency additions
