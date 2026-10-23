## Context

Every raw TCP trap had an identical `Start`, `Stop` and handler prefix. `Stop` waited on a wait group that only drained when clients left, so shutdown took up to `SessionTimeout` and tests that kept a client open waited 5 seconds each. The run loop bounds shutdown with an 8 second context but `Stop` ignored it.

## Decisions

### Skeleton shape
`tcpServer` holds protocol, config, logger, metrics, limiter, reporter and a handler `func(ctx context.Context, conn net.Conn, sess *Session)`. Traps embed `*tcpServer` and get `Start`, `Stop` and `Addr` from it. The trap struct keeps only what its handler needs.

### Accept path
`Start` listens with `ListenMultiTCP` (keeps PROXY protocol and the accept backoff), then loops on `Accept`. Each accepted connection is dispatched inside `safely`. Dispatch order: refuse if stopping, `limiter.Acquire` (reject and close on failure), register the connection and `wg.Add(1)` under the server mutex, then `go serve`. Acquiring before the spawn bounds goroutines by the limiter, not by the connection rate. A closed listener (`net.ErrClosed`) ends the loop, which also fixes the spin on `Stop` without a context cancel.

### Serve path
`serve` derives a per-connection context from the `Start` context and calls `context.AfterFunc(connCtx, conn.Close)`. It builds the session (`NewSession`, `Sensor`), logs connect, records start and end, sets the deadline with `ResolveSessionTimeout`, runs the handler inside `safely`, and releases the limiter slot in a defer that survives panics.

### Stop
`Stop(ctx)` sets the stopping flag under the mutex, closes the listener, cancels every tracked connection context and closes every tracked connection, then waits for the wait group in a helper goroutine. It returns `nil` when the group drains and `ctx.Err()` when the context ends first. Further calls repeat the idempotent close and wait. A `Start` that begins after `Stop` closes its listener and returns.

### Deadlines
`deadlineFromContext` keeps the earlier of the context deadline and `now+timeout`. Cancellation needs no extra handling because the connection is closed when the context ends, so blocked reads return at once.

### Line helper
A shared line loop was evaluated for pop3, ftp, imap, irc and smtp. The protocols differ in scanner buffer size, banner timing, error mapping and quit handling, so a helper would need enough hooks to be harder to read than the loops. It is not introduced.

## Risks

- Sessions in flight at shutdown are cut instead of drained. Honeypot sessions carry no state worth draining, and the old drain was bounded by an 8 second abandon anyway.
- The `Start` context cancel closes connections, so handlers that previously finished a final write after cancel now see a closed connection and end with outcome `error` or `timeout`.
