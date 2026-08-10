## Context

RAN is a Go honeypot with 27 traps. During development, a few code-quality issues crept in: an unused WaitGroup, a stdlib-duplicate helper, and a non-graceful HTTP server shutdown. All three are mechanical fixes with no behavioral risk.

## Goals / Non-Goals

**Goals:**
- Remove dead code to reduce maintenance burden
- Use stdlib where a local helper is redundant
- Shut down the metrics HTTP server gracefully

**Non-Goals:**
- Refactoring trap architecture or lifecycle
- Adding tests for these changes (the fixes are trivially correct)

## Decisions

1. **Remove `wg` field entirely** rather than wiring it up. The HTTP trap's connection handling does not need a WaitGroup — the listener close already drains connections.

2. **Direct `io.ReadFull` replacement**. The custom `readFull` in `rdp.go` has identical semantics to `io.ReadFull` (loop reading until buf is full or error). Swap call sites and delete the function.

3. **`Shutdown(ctx)` with 5-second timeout** for the metrics server. `Close()` drops in-flight scrape requests; `Shutdown` lets them finish within the deadline. Five seconds is generous for a `/metrics` endpoint.

## Risks / Trade-offs

- [Minimal risk] All changes are removals or stdlib swaps with no new logic.
- [Shutdown timeout] If a Prometheus scrape is stuck, `Shutdown` blocks up to 5 s before the process exits. Acceptable for an orderly drain.
