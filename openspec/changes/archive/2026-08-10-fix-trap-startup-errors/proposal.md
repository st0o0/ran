## Why

Trap startup errors in `cmd/ran/run.go` are silently lost. The `errc` channel receives errors from each trap's `Start()` goroutine but is never read. If a trap fails to bind its port or encounters a startup error, the operator gets no feedback and the honeypot runs with missing coverage.

## What Changes

- Read from `errc` after launching all trap goroutines to collect startup results.
- Log each individual trap startup failure at Error level and continue running healthy traps.
- If ALL traps fail to start, cancel the context and return an error (fail-fast).
- `run()` continues to block on `ctx.Done()` when at least one trap is healthy.

## Capabilities

### New Capabilities

- `trap-startup-handling`: Error collection and fail-fast logic for trap startup in the orchestrator.

### Modified Capabilities

_(none — existing trap specs define per-trap behavior; this change is orchestrator-level)_

## Impact

- `cmd/ran/run.go`: primary change site (lines 30-35).
- No API or config changes. No new dependencies.
- All 27 existing traps benefit without modification.
