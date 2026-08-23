## ADDED Requirements

### Requirement: Configurable escalating auth delay
Handlers SHALL support an optional delay before sending auth failure responses, controlled by `RAN_AUTH_DELAY` (global default, default `0s` meaning disabled) and `RAN_<PROTO>_AUTH_DELAY` (per-protocol override). The delay SHALL escalate exponentially per attempt within a session: `baseDelay × 2^attempt`, capped at `4 × baseDelay`.

#### Scenario: Delay disabled by default
- **WHEN** `RAN_AUTH_DELAY` is not set (default `0s`)
- **THEN** handlers SHALL respond to auth failures immediately with no artificial delay

#### Scenario: Escalating delay
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client makes 4 attempts
- **THEN** the delays before each response SHALL be: attempt 0 = 2s, attempt 1 = 4s, attempt 2 = 8s, attempt 3 = 8s (capped at 4× base)

#### Scenario: Per-protocol override
- **WHEN** `RAN_AUTH_DELAY=1s` and `RAN_SSH_AUTH_DELAY=3s` are set
- **THEN** SSH auth responses SHALL be delayed starting at 3s, other handlers starting at 1s

#### Scenario: Delay capped at 4× base
- **WHEN** `RAN_AUTH_DELAY=2s` is set and a client reaches attempt 5
- **THEN** the delay SHALL remain at 8s (4 × 2s), not escalate further

### Requirement: Context-aware delay
The auth delay SHALL respect the session deadline. If the session context is cancelled during the delay, the handler SHALL return immediately with outcome `"timeout"`.

#### Scenario: Timeout during delay
- **WHEN** a 2s auth delay is in progress and the session deadline expires
- **THEN** the handler SHALL stop waiting, set outcome `"timeout"`, and close the connection

#### Scenario: Delay does not extend session
- **WHEN** the session timeout is 30s and total accumulated delays exceed 30s
- **THEN** the session SHALL end at the 30s deadline, not extend to accommodate remaining delays

### Requirement: Shared delay helper
A shared `authSleep(ctx context.Context, baseDelay time.Duration, attempt int) error` function SHALL be available to all handlers. It SHALL return `nil` on successful sleep completion, or `ctx.Err()` if the context was cancelled.

#### Scenario: Helper returns nil on success
- **WHEN** `authSleep(ctx, 2s, 0)` is called and context is not cancelled within 2s
- **THEN** the function SHALL return `nil` after sleeping 2s

#### Scenario: Helper returns error on cancellation
- **WHEN** `authSleep(ctx, 10s, 0)` is called and context is cancelled after 3s
- **THEN** the function SHALL return `ctx.Err()` after 3s
