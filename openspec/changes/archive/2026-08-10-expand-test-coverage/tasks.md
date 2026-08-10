## 1. Trap package unit tests

- [x] 1.1 Create `internal/trap/trap_test.go` with `TestParseAddr` covering valid host:port, port-only, and invalid port inputs
- [x] 1.2 Add `TestNewSession` validating protocol, source IP, port fields, and non-empty session ID
- [x] 1.3 Add `TestDeadlineFromContext` for background context (timeout-based) and context with earlier deadline

## 2. Metrics package unit tests

- [x] 2.1 Create `internal/metrics/metrics_test.go` with `TestNew` verifying non-nil return and all collector fields populated
- [x] 2.2 Add test for duplicate registration behavior (no panic on second call)

## 3. Run function unit tests

- [x] 3.1 Create `cmd/ran/run_test.go` with `TestRunSuccess` using a minimal config with one trap on an ephemeral port
- [x] 3.2 Add `TestRunPartialFailure` configuring multiple traps where one binds to a conflicting port
- [x] 3.3 Add `TestRunTotalFailure` where all configured traps fail to start, asserting error return

## 4. Extended integration tests

- [x] 4.1 Add FTP trap integration test: connect to FTP port, assert 220 banner
- [x] 4.2 Add Telnet trap integration test: connect to Telnet port, assert login prompt or negotiation bytes
- [x] 4.3 Add Redis trap integration test: send PING, assert RESP reply

## 5. Verification

- [x] 5.1 Run `go test ./...` and confirm all new and existing tests pass
- [ ] 5.2 Run `go test -race ./...` to check for data races in new tests (requires CGO_ENABLED=1, skipped on Windows)
