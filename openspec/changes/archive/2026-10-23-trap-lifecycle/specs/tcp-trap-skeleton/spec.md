## ADDED Requirements

### Requirement: Shared TCP accept and session skeleton
All raw TCP traps SHALL run on one shared skeleton that owns listening (including PROXY protocol and accept backoff), the accept loop, limiter handling, session creation and wiring, session metrics, disconnect logging and panic safety. A trap SHALL only provide a handler that receives the context, the connection and the prepared session.

#### Scenario: Handler receives a prepared session
- **WHEN** a client connects to a TCP trap
- **THEN** the handler is called with a session whose protocol, transport, source IP, ports and sensor are set and whose deadline is `ResolveSessionTimeout` for that protocol

#### Scenario: Panic in a handler
- **WHEN** a handler panics
- **THEN** the panic is counted and logged, the limiter slot is released, the session is ended and other connections continue

### Requirement: Limiter before goroutine
The skeleton SHALL acquire the limiter slot before it spawns the connection goroutine. A connection that is refused SHALL be closed, logged as rejected with reason `rate_limit`, and SHALL NOT create a goroutine.

#### Scenario: Connection flood
- **WHEN** a client opens more connections than the per-IP limit allows
- **THEN** the number of live connection goroutines never exceeds the limit

### Requirement: Stop closes active connections
`Stop(ctx)` SHALL close the listener and every live connection immediately, and SHALL wait for the connection goroutines. When `ctx` ends before they finish, `Stop` SHALL return `ctx.Err()`. `Stop` SHALL be safe to call more than once and SHALL NOT race with a concurrent `Start`.

#### Scenario: Idle client at shutdown
- **WHEN** a client is connected and idle with a 30 second session timeout and `Stop` is called
- **THEN** the client connection is closed and `Stop` returns in well under one second

#### Scenario: Context deadline
- **WHEN** workers do not finish before the `Stop` context deadline
- **THEN** `Stop` returns the context error at the deadline

#### Scenario: Repeated stop
- **WHEN** `Stop` is called twice
- **THEN** both calls return without error and without panic

### Requirement: Start context cancellation ends sessions
Cancelling the context passed to `Start` SHALL close the listener and all live connections, so no handler waits for the session timeout after cancellation.

#### Scenario: Cancel with open client
- **WHEN** the `Start` context is cancelled while a client is idle
- **THEN** the connection is closed and the handler returns promptly
