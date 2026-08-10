## Why

The codebase has accumulated minor dead code and suboptimal patterns: an unused sync.WaitGroup in the HTTP trap, a hand-rolled `readFull` that duplicates `io.ReadFull`, and a hard `Close()` on the metrics server instead of a graceful `Shutdown()`. Cleaning these up reduces maintenance surface and improves shutdown behavior.

## What Changes

- Remove unused `wg sync.WaitGroup` field from `HTTPTrap` and the `t.wg.Wait()` call in its `Stop()` method.
- Replace custom `readFull` helper in `internal/trap/rdp.go` with stdlib `io.ReadFull`.
- Change `metricsSrv.Close()` to `metricsSrv.Shutdown(ctx)` with a 5-second timeout in `cmd/ran/main.go`.

## Capabilities

### New Capabilities

- `dead-code-removal`: One-off cleanup removing unused fields, redundant helpers, and improving shutdown hygiene.

### Modified Capabilities

_(none — these are implementation-only fixes with no spec-level behavior changes)_

## Impact

- `internal/trap/http.go` — struct field and Stop() method change
- `internal/trap/rdp.go` — remove local function, add `io` import
- `cmd/ran/main.go` — metrics server shutdown call and new timeout context
