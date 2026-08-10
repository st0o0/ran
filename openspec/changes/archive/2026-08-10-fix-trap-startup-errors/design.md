## Context

`run()` in `cmd/ran/run.go` launches each trap in a goroutine that sends its `Start()` error into a buffered `errc` channel. The channel is never drained, so startup failures are silently discarded. The function immediately blocks on `ctx.Done()` regardless of whether any trap actually started.

## Goals / Non-Goals

**Goals:**

- Surface every trap startup failure via structured logging.
- Fail fast when zero traps start successfully.
- Preserve current behavior (block on `ctx.Done()`) when at least one trap is healthy.

**Non-Goals:**

- Retry logic or automatic recovery for failed traps.
- Health-check endpoints or readiness probes.
- Changes to the `trap.Trap` interface or individual trap implementations.

## Decisions

### 1. Synchronous drain after launch

Read `len(traps)` values from `errc` immediately after all goroutines are spawned. This reuses the existing buffered channel and requires no new synchronization primitives.

*Alternative*: Use a `sync.WaitGroup` alongside the channel. Rejected because the channel already carries the error value and is correctly sized.

### 2. Log-and-continue for partial failures

Each non-nil error is logged at `slog.Error` level with the trap index or name. The healthy-trap count is tracked. Only when all traps fail does `run()` return an error.

*Alternative*: Fail on first error. Rejected because a honeypot with 26/27 traps running is still valuable.

### 3. Context cancellation on total failure

When `failCount == len(traps)`, cancel the context (requires changing `run()` to accept or create a cancellable context) and return a descriptive error. This prevents the process from hanging with nothing listening.

## Risks / Trade-offs

- **[Startup timing]** A trap's `Start()` must return (or error) promptly for the drain loop to complete. Current traps call `net.Listen` then return nil, sending traffic handling into a separate goroutine, so this is safe. Future traps that block in `Start()` would stall the drain. Mitigation: document the contract in the spec.
- **[Partial degradation]** Running with failed traps may surprise operators who expect all-or-nothing. Mitigation: Error-level log lines make failures visible; monitoring can alert on them.
