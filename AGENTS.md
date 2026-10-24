# AGENTS.md

Notes for AI agents and contributors working on `ran`. Keep it short and factual; update it when a lesson changes.

## Conventions

- Commits follow Conventional Commits (see `commitlint.config.mjs`), one line, no body. `release-please` derives the version and `CHANGELOG.md` from the commit titles. Never edit `CHANGELOG.md` or `.release-please-manifest.json` by hand.
- Use `fix:`/`feat:` for user-visible changes and `chore:`/`docs:` for the rest. Mark breaking behavior with `!` in the title, because `release-please` reads it.
- Specs and changes live in `openspec/` (tracked). Create changes with the `openspec` CLI, run `openspec validate --all`, sync delta specs to the main specs when archiving.
- English only in code, comments, docs and commit messages. No em dashes (use `--`).
- No real IP addresses or personal domains in code, tests or docs. Test addresses: use well-known public addresses (for example `8.8.8.8`, `1.1.1.1`, `2606:4700:4700::1111`). Documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) are on the alert denylist and are rejected by the CrowdSec sink (pipeline stage `invalid`), so do not use them where an alert must be accepted.

## Verification

- The host may have no C compiler. Run the race detector in Docker: `golang:1.26.10` (matches `go.mod`; raised from 1.26.1 for the stdlib fixes govulncheck reports in 1.26.2 and later; CI reads the version from `go.mod`; the Dockerfile builder stays on `golang:1.27-alpine`), repo copied or mounted, `go test -race ./...`.
- The `internal/trap` suite takes about 5 to 10 seconds (it was about two minutes before the shared TCP skeleton, when shutdown waited for idle clients). Start traps in tests on port 0 with `serveTrap`/`startTrap` (`startup_test.go`) instead of picking a port and sleeping; mark tests `t.Parallel()` unless they touch package-level state.
- Lint with the pinned image `golangci/golangci-lint:v2.15.0` and the repo config. Compare against `git archive HEAD` so only new findings count.
- Fuzz targets (run at least 60 seconds after touching the matching parser, CI runs each for 20 seconds): `FuzzRedisCommand`, `FuzzBERReadElement`, `FuzzParseV1V2`, `FuzzParseNTLMSSPAuth`, `FuzzReadPgStartup`, `FuzzParseTDSLogin7`, `FuzzParseDNSName`, `FuzzParseMQTTConnect`, `FuzzReadTNSPacket`, `FuzzReadMySQLPacket`, `FuzzReadMQTTVarInt`, `FuzzHTTPMatchers`, `FuzzParseClientHello`, `FuzzParseKexInit`, `FuzzReadMongoMessage`, `FuzzParseDockerBody`, `FuzzFormCommand`, `FuzzTelnetIAC`, `FuzzReadADBPacket`, `FuzzParseModbusPDU` (the last eighteen live in `internal/trap/fuzz_test.go` and share a "must not panic, output bounded by input" contract). Run one with `go test -run=^$ -fuzz=^FuzzName$ -fuzztime=60s ./internal/trap/`.
- `FuzzParseIgnoreList` (`internal/config/ignore_test.go`) covers the `RAN_IGNORE_IPS` parser: run it for 60 seconds after touching it (`go test -run=^$ -fuzz=^FuzzParseIgnoreList$ -fuzztime=60s ./internal/config/`).
- Also run `go vet` and `go build` for `GOARCH=386`, because some length checks depend on the size of `int`. Run `openspec validate --all` after touching `openspec/`. `ran check-config` validates an environment without starting traps.
- Contract tests: `internal/config/contract_test.go` fails when README and config disagree on `RAN_*` variables (document every new variable in the README; per-trap variables are covered by the `RAN_<PROTO>_...` rows), and `internal/trap/registry_test.go` fails when `config.DefaultPorts`, `config.ValidTraps` and `trap.Registry` differ. A new trap needs entries in all three.
- Tests that touch package-level state (for example `panicLog`) must swap in a fresh instance and restore it, otherwise `-count=N` runs become flaky. Log buffers that goroutines write to must be mutex guarded (`syncBuffer`, `lockedBuffer`). Time-dependent code takes an injectable clock.

## Rules for traps (security checklist)

- A trap must never trust client-supplied identity. The alert IP is the socket peer. Header values (`X-Forwarded-For`, `X-Real-IP`) are logged only (`claimed_client_ip`).
- UDP traps must never alert: source addresses are spoofable. They log and emit metrics only, and the handler has no alerter field, so this holds structurally. UDP handling is rate limited before a goroutine is spawned.
- Every read is bounded: use `readLineLimited` for line input, cap any count or length before `make`, and use `fitsInt` for lengths decoded from 32-bit fields. Never size an allocation from client input.
- Raw TCP traps run on the shared skeleton in `internal/trap/tcpserver.go`: a trap embeds `*tcpServer` (built with `newTCPServer(proto, cfg, logger, m, limiter, alerter, t.handle)`) and only implements `handle(ctx, conn, sess)`. Do not copy `Start`/`Stop`/accept code into a trap. The skeleton enforces the checklist below: listening with PROXY protocol and accept backoff, `limiter.Acquire` before the goroutine is spawned, `wg.Add` before the spawn (ordered against `Stop` by a mutex), session creation with `Sensor` set, `ResolveSessionTimeout` deadline, start/end metrics, disconnect log, `safely` around accept dispatch and handler, and `context.AfterFunc` closing the connection when the context ends. `Stop(ctx)` closes the listener and all live connections, returns `ctx.Err()` if workers outlive `ctx`, and is idempotent. A handler never closes the connection itself, never sets the sensor, and must not wait on anything that ignores `ctx` or a closed connection.
- HTTP traps keep `http.Server` (sessions per connection via `ConnContext`/`ConnState`) and UDP traps keep `UDPTrap`; both follow the same `Stop(ctx)` contract and expose `Addr()`/`Ready()` for tests. `docker` and `kubernetes` embed `*HTTPTrap` and only replace the handler with `setHandler`; do not copy the connection plumbing.
- Wrap handlers, accept loops and packet handlers in `safely` so one panic does not stop all traps. Log volume of recovered panics is rate limited; the counter is not.
- Sources in `RAN_IGNORE_IPS` are decided in `Sensor` (`Alert`, `SessionEnd`, `touchScan`): a new code path that classifies, tracks or reports a session must go through the sensor so the ignore check applies. Traps set the sensor with `sess.UseSensor` (never assign `sess.Sensor` directly), which adds the `ignored=true` log marker; UDP traps get the list through `withIgnore(cfg)`.
- Metric labels must come from a bounded set (protocol names), never from client data.
- Traps depend on the small `trap.Reporter` interface (Alert, SessionEnd), not on the sensor lifecycle. Use `setOutcome`/`isTimeout` for I/O errors, `Session.Cred` for plain username and password capture, and `cfg.ResolveSessionTimeout(proto)` for deadlines. Sessions carry a typed `alert.Transport`.
- HTTP sessions are keyed by the connection (`ConnContext`), never by `RemoteAddr`: under PROXY protocol the address is client controlled and can collide.
- Passwords are never sent to CrowdSec as event meta. Logging them is controlled by `RAN_LOG_PASSWORDS` (default `off`).
- With `RAN_PROXY_PROTOCOL` on, the PROXY header is required, handshakes are capped and time boxed. Only enable it when `ran` is reachable solely from a trusted proxy or tunnel; any direct peer can forge a header.

## CrowdSec integration facts (verified against v1.8.1)

- LAPI profiles are skipped for alerts that already carry decisions. `ran` 0.3.x embedded a ban decision, so profile based escalation never ran for `custom/ran-*`. From 0.4.0 `ran` pushes alerts without decisions (`remediation: true`, `source.value` and `source.ip` set, class meta on the event) so profiles decide. The default profile then creates the decision with origin `crowdsec`.
- Profiles read the class with `Alert.Events[0].GetMeta("class")`. `Alert.GetMeta` reads only alert level meta.
- LAPI allowlists apply only to alerts without embedded decisions; an embedded decision stays ban-listed.
- `GetDecisionsCount` counts decision rows of alerts still stored in the database, including expired rows and rows removed with `cscli decisions delete`. The database flush at `db_config.flush.max_items` deletes alerts without an active decision, and those rows then drop out of the count, which lowers the escalation level. Size `max_items` and `max_age` so the history covers the longest escalation step.
- A profile `duration_expr` must produce a float for `Sprintf('%.0fh', ...)`. `min(168, 3 ^ n)` returns the int literal at the cap and `%.0f` then fails silently, falling back to the base duration. Use `min(168.0, ...)`. Capital `Min` does not compile and CrowdSec exits at startup. `crowdsec -t` only compiles the expression and does not catch the formatting issue.
- Alerts flagged `simulated: true` create a decision that the bouncer stream does not enforce and are not shared to the community blocklist; any other alert is shared, even without decisions.
- The plugin channel of the CrowdSec notification broker is unbuffered; bursts can drop notifications. This is not a `ran` problem.

## Known follow-ups

The planned work, its order and the rejected ideas live in `todo.md`. Keep it in sync with `openspec/changes/`. The items below are small leftovers that are not yet in a change.

- PROXY protocol: no source allowlist for who may send headers.
- Per-trap classification: meta for vnc and the remaining single-request traps.
- Weak-yield traps (mssql, mqtt, memcached, adb, minecraft, elasticsearch) are candidates for removal once breadth based scan detection has produced real numbers; decide with data.
