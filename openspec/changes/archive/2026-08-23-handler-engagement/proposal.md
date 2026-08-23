## Why

Four protocol handlers (SSH, MSSQL, Telnet, SMB) have 84-100% error rates because they are "one-shot" — they handle a single auth attempt and close the connection. This is both unrealistic (real services allow retries) and wasteful (fewer credentials captured, attackers reconnect immediately). SSH has an additional design bug where every session is classified as "error" because the crypto library treats a rejected auth as a handshake failure. Adding multi-auth loops, configurable response delays, and an SSH-specific pre-auth tarpit will make these handlers more realistic, capture more credentials per session, and waste attacker time.

## What Changes

- **SSH outcome fix**: track whether PasswordCallback fired; classify as "completed" when auth was attempted, "error" only for real handshake failures
- **Multi-auth retries**: one-shot handlers (SSH, Telnet, MSSQL, SMB, VNC) gain configurable retry loops matching real service behavior
- **Auth delay (escalating tarpit)**: configurable base delay before auth responses, escalating exponentially per attempt (capped at 4× base), applicable to all handlers
- **SSH pre-auth tarpit**: endlessh-style random banner line drip before presenting the real SSH banner, configurable duration
- **Probe outcome**: new `"probe"` outcome for connections that never sent valid protocol data (port scanners), distinct from `"error"` (real I/O failures)
- **Per-protocol config overrides**: `RAN_<PROTO>_MAX_AUTH_RETRIES`, `RAN_<PROTO>_AUTH_DELAY`, `RAN_<PROTO>_SESSION_TIMEOUT` following the existing `RAN_<PROTO>_ADDR` pattern

## Capabilities

### New Capabilities
- `multi-auth`: configurable auth retry loops for one-shot handlers, with global default and per-protocol overrides via env vars (0 = unlimited)
- `auth-delay`: escalating response delay before auth failure responses, with global default and per-protocol overrides (0 = disabled), exponential backoff capped at 4× base
- `ssh-tarpit`: endlessh-style pre-auth tarpit that sends random banner lines at 10s intervals before presenting the real SSH-2.0 banner, configurable duration and on/off toggle

### Modified Capabilities
- `config`: new env vars — `RAN_MAX_AUTH_RETRIES` (default 3), `RAN_AUTH_DELAY` (default 0s), `RAN_SSH_TARPIT` (default off), `RAN_SSH_TARPIT_DURATION` (default 30s), per-protocol `RAN_<PROTO>_SESSION_TIMEOUT`, `RAN_<PROTO>_MAX_AUTH_RETRIES`, `RAN_<PROTO>_AUTH_DELAY`
- `connection-outcomes`: add `"probe"` as fourth outcome value for scanner connections that never produced valid protocol data
- `trap-ssh`: outcome fix (authSeen flag), MaxAuthTries from config, tarpit phase before handshake, auth delay between attempts
- `trap-telnet`: login prompt retry loop with configurable max retries and auth delay
- `trap-mssql`: TDS login retry loop after prelogin, with configurable max retries and auth delay; classify non-TDS connections as "probe"
- `trap-smb`: session setup retry loop with configurable max retries; classify non-SMB connections as "probe"
- `metrics`: `ran_connections_total` outcome label gains `"probe"` value

## Impact

- **Config** (`internal/config/config.go`): new fields on Config struct, new env var parsing, per-protocol override resolution helper
- **Session** (`internal/trap/trap.go`): no struct changes, but handlers will use new config fields to drive loops and delays
- **Metrics** (`internal/metrics/metrics.go`): no code change needed — `"probe"` is just a new label value on the existing counter
- **Handlers** (`internal/trap/ssh.go`, `telnet.go`, `mssql.go`, `smb.go`): loop logic, delay insertion, outcome classification changes
- **Tests**: all affected handler tests need updates for multi-attempt flows and new outcomes
- **Docs/deployment**: env var documentation update, example deployment configs
