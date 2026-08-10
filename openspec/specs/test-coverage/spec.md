# test-coverage Specification

## Purpose
TBD - created by archiving change expand-test-coverage. Update Purpose after archive.
## Requirements
### Requirement: ParseAddr unit tests
The test suite SHALL validate `ParseAddr` for standard `host:port` input, port-only input (`:8022`), and invalid/missing port values.

#### Scenario: Valid host and port
- **WHEN** `ParseAddr("0.0.0.0:8022")` is called
- **THEN** it returns host `"0.0.0.0"` and port `8022`

#### Scenario: Port-only address
- **WHEN** `ParseAddr(":8080")` is called
- **THEN** it returns an empty host and port `8080`

#### Scenario: Invalid port
- **WHEN** `ParseAddr("host:notanumber")` is called
- **THEN** it returns port `0` (or the defined fallback)

### Requirement: NewSession unit tests
The test suite SHALL validate that `NewSession` populates protocol, source IP, port, and generates a non-empty session ID.

#### Scenario: Session fields populated
- **WHEN** `NewSession("ssh", "192.168.1.1", 8022)` is called
- **THEN** the returned `Session` has `Protocol == "ssh"`, `SourceIP == "192.168.1.1"`, `Port == 8022`, and a non-empty `ID`

### Requirement: deadlineFromContext unit tests
The test suite SHALL validate deadline computation from context with and without an existing deadline.

#### Scenario: Context without deadline
- **WHEN** `deadlineFromContext` is called with a background context and a 5s timeout
- **THEN** the returned deadline is approximately `now + 5s`

#### Scenario: Context with earlier deadline
- **WHEN** the context has a deadline sooner than the provided timeout
- **THEN** the returned deadline matches the context's deadline

### Requirement: Metrics registration tests
The test suite SHALL verify that `metrics.New()` registers all expected Prometheus collectors without panicking on duplicate registration.

#### Scenario: Successful registration
- **WHEN** `metrics.New(prometheus.NewRegistry())` is called
- **THEN** it returns a non-nil `*Metrics` and all counter/histogram fields are non-nil

#### Scenario: No duplicate registration panic
- **WHEN** `metrics.New()` is called twice with the same registry
- **THEN** the second call either succeeds or returns an error (no panic)

### Requirement: run() orchestration tests
The test suite SHALL validate the `run()` function for full success, partial failure, and total failure.

#### Scenario: Successful startup
- **WHEN** `run()` is called with a valid config enabling at least one trap
- **THEN** all enabled traps start listening and `run()` blocks until context cancellation

#### Scenario: Partial failure
- **WHEN** some traps fail to bind (e.g., port conflict) but at least one succeeds
- **THEN** `run()` logs errors for failed traps and continues serving with the successful ones

#### Scenario: Total failure
- **WHEN** all configured traps fail to start
- **THEN** `run()` returns an error

### Requirement: Extended integration tests
The integration test SHALL cover FTP, Telnet, and Redis traps in addition to existing SSH, HTTP, and MySQL coverage.

#### Scenario: FTP trap responds
- **WHEN** a TCP connection is made to the FTP trap port
- **THEN** the trap sends an FTP banner (220 response)

#### Scenario: Telnet trap responds
- **WHEN** a TCP connection is made to the Telnet trap port
- **THEN** the trap sends a Telnet negotiation or login prompt

#### Scenario: Redis trap responds
- **WHEN** a TCP connection sends a `PING` command to the Redis trap port
- **THEN** the trap responds with `+PONG` or a Redis-compatible response

