## 1. Implementation

- [x] 1.1 Add `internal/trap/tcpserver.go`: `tcpServer` with listen (`ListenMultiTCP`), accept loop in `safely`, limiter acquire before spawn, `wg.Add` before spawn under a mutex, tracked connections, `context.AfterFunc` close, session wiring, metrics, disconnect log
- [x] 1.2 `Stop(ctx)` closes the listener and live connections, returns `ctx.Err()` when workers outlive the context, and is idempotent; `Start` after `Stop` returns at once
- [x] 1.3 Migrate the 22 raw TCP traps (telnet, pop3, ftp first, then the rest) onto the skeleton and delete their duplicated `Start`, `Stop` and handler prefix
- [x] 1.4 HTTP traps expose `Addr()`/`Ready()`; dead wait groups removed from httpproxy and elasticsearch
- [x] 1.5 UDP trap: mutex-guarded socket list, `wg.Add` before the read loops, `Stop(ctx)` honours the context, `Start` returns after `Stop`
- [x] 1.6 `deadlineFromContext` yields `now` for a cancelled context; `MultiListener.Close` closes connections that were accepted but never taken
- [x] 1.7 Line helper for pop3, ftp, imap, irc and smtp evaluated and skipped (loops differ in buffer size, banner timing, error mapping and quit handling; see design.md)
- [x] 1.8 AGENTS.md: skeleton conventions; README: shutdown behavior note

## 2. Tests

- [x] 2.1 `serveTrap`/`startTrap` helpers (port 0, ready signal, stop on cleanup) and migration of the port-pick and sleep startup in existing tests
- [x] 2.2 Shorter waits and `t.Parallel()` for independent tests; suite time from about 117s to under 10s
- [x] 2.3 Lifecycle tests: idle client closed by `Stop` in under a second with a 30s session timeout, `Stop` honours its context deadline (TCP and UDP), idempotent `Stop`, rapid start and stop, limiter acquired before the goroutine under a flood, start context cancel closes clients, no goroutine leak
- [x] 2.4 Persistent cap test: scan tracker, probe log and cooldown filter stay at `MaxTracked` (100k) under a flood of unique sources
- [x] 2.5 End-to-end test: trap, Sensor, CrowdSec sink and an httptest LAPI (login, 401 re-login, batch splitting, JSON payload with `remediation`, empty `decisions`, `source.value`/`source.ip`, event meta class, scenario `custom/ran-telnet-trap`)
- [x] 2.6 goleak not added (not in `go.mod`; avoids a new dependency); goroutine counts via `runtime.NumGoroutine` instead
