## ADDED Requirements

### Requirement: No unused struct fields in trap implementations
Trap structs SHALL NOT contain fields that are never read or written after construction.

#### Scenario: HTTPTrap has no WaitGroup field
- **WHEN** the `HTTPTrap` struct is defined in `internal/trap/http.go`
- **THEN** it SHALL NOT contain a `wg sync.WaitGroup` field

### Requirement: Use stdlib over duplicate helpers
Trap implementations SHALL use Go standard library functions when a local helper duplicates stdlib behavior.

#### Scenario: RDP trap uses io.ReadFull
- **WHEN** the RDP trap needs to read exactly N bytes from a connection
- **THEN** it SHALL call `io.ReadFull` instead of a custom `readFull` function

### Requirement: Graceful metrics server shutdown
The metrics HTTP server SHALL shut down gracefully, allowing in-flight requests to complete within a bounded timeout.

#### Scenario: Metrics server stops on signal
- **WHEN** the process receives a shutdown signal
- **THEN** the metrics server SHALL call `Shutdown(ctx)` with a 5-second timeout context
- **THEN** in-flight `/metrics` scrapes SHALL be allowed to complete within the timeout
