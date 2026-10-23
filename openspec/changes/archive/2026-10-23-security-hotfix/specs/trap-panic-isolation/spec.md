## ADDED Requirements

### Requirement: Panics are contained per connection
Every per-connection handler goroutine, listener accept goroutine and UDP per-packet goroutine SHALL recover from panics, increment `ran_panics_recovered_total{protocol}` for every panic, log the panic at error level, and release held limiter slots. Logs SHALL be rate limited per protocol: a stack trace for the first 5 panics, then at most one log per second without a stack. HTTP handler panics SHALL be counted and logged once by a wrapper around the handler. The process SHALL keep serving other traps and connections.

#### Scenario: Handler panics
- **WHEN** a trap handler panics on malformed input
- **THEN** only that connection ends, the counter increments and other traps continue

#### Scenario: Panic storm
- **WHEN** a handler panics 50 times in one second
- **THEN** the counter is 50 and at most 5 panic logs are written

#### Scenario: HTTP handler panics
- **WHEN** an HTTP trap handler panics
- **THEN** the counter increments once, one log line is written and the connection is aborted

#### Scenario: Limiter slot released
- **WHEN** a handler panics after acquiring a limiter slot
- **THEN** the slot is released

#### Scenario: Accept panics repeatedly
- **WHEN** a listener's `Accept` panics on every call
- **THEN** the accept goroutine sleeps between attempts (10ms doubling to 1s, reset after a successful accept), so it does not spin a CPU, and `Close` still returns promptly
