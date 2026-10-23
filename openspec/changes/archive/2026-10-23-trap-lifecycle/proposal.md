## Why

All 22 raw TCP traps repeat the same ~73 lines of listen, accept, limiter, session and shutdown code, and the copy has real defects: `Stop(ctx)` ignores its context and waits for every client to disconnect (up to `SessionTimeout`), `wg.Add` runs after `Accept` so it can race with `Wait`, the listener field is written and read without synchronization, the limiter is acquired inside the connection goroutine (a flood spawns an unbounded number of goroutines), and `Stop` without a context cancel spins on a closed listener. The `internal/trap` test suite also takes about 117 seconds because 20 tests wait for the 5 second session timeout on shutdown.

## What Changes

- New shared TCP skeleton (`tcpServer`) that owns listen, accept loop, limiter, session wiring, metrics, panic safety and shutdown. Traps provide only a handler `func(ctx, conn, sess)`.
- `Stop(ctx)` closes all live connections immediately, is idempotent, and returns `ctx.Err()` when workers do not finish before the context deadline.
- The limiter slot is acquired before the connection goroutine is spawned; rejected connections never create a goroutine.
- `wg.Add` happens before the goroutine is spawned and is ordered against `Stop` with a mutex, so there is no Add-after-Wait race.
- Cancelling the context given to `Start` closes live connections too, so no handler waits for `SessionTimeout` after shutdown began.
- UDP traps honour the `Stop` context deadline as well.
- The 22 raw TCP traps migrate onto the skeleton; protocol behavior, outcomes, metrics and PROXY protocol handling stay the same. The three HTTP-based traps keep `http.Server` but follow the same `Stop` contract.
- **BREAKING** (behavior): shutdown no longer lets active sessions drain. They are closed at once when the trap stops.
- Tests start traps on `:0` and read the bound address instead of picking a port and sleeping; new tests cover the lifecycle guarantees, the persistent cap of the tracked structures and an end-to-end trap to CrowdSec sink path.

## Capabilities

### New Capabilities

- `tcp-trap-skeleton`: one accept and session skeleton for all raw TCP traps, with the shutdown contract.

### Modified Capabilities

- `lifecycle`: graceful shutdown closes active sessions and is bounded by the shutdown context.
- `udp-trap-base`: `Stop` honours its context deadline.

## Impact

- `internal/trap`: new `tcpserver.go`, all TCP trap files lose their listener, wait group, `Start`, `Stop` and handler prefix; `udp.go` `Stop`; `deadlineFromContext`.
- README: shutdown behavior note. AGENTS.md: skeleton conventions.
- No config, metric or alert-format changes.

## Non-goals

- No protocol behavior changes, no new traps, no table-driven protocol handlers.
- No change to the PROXY protocol listener or the multi-listener accept backoff.
- No change to UDP session semantics (still no alerts from UDP).
