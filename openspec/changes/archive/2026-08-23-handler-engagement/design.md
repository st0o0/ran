## Context

Ran's protocol handlers fall into two categories: "loop" handlers (SMTP, FTP, POP3, etc.) that maintain a command loop allowing multiple auth attempts per session, and "one-shot" handlers (SSH, Telnet, MSSQL, SMB) that handle a single auth attempt and close. The one-shot handlers show 84-100% error rates in production metrics, partly due to scanner noise but also due to a design flaw in SSH where the golang.org/x/crypto library treats a rejected PasswordCallback as a handshake error.

The system currently has a single global `RAN_SESSION_TIMEOUT` and no mechanism for response delays or pre-auth tarpitting. All configuration follows the `RAN_` prefix env var pattern with per-protocol overrides via `RAN_<PROTO>_*`.

## Goals / Non-Goals

**Goals:**
- Fix SSH outcome classification so auth-rejected sessions count as "completed"
- Add configurable multi-auth retry loops to one-shot handlers
- Add escalating response delay (tarpit) to waste attacker time on all handlers
- Add SSH-specific endlessh-style pre-auth tarpit
- Distinguish scanner probes from real protocol errors in metrics
- Keep all features configurable and individually disablable via env vars

**Non-Goals:**
- Modifying loop-based handlers (SMTP, FTP, POP3, etc.) — they already work well
- Adding auth delay to UDP-based handlers (SIP, DNS, NTP, SNMP) — connectionless protocols don't benefit from tarpitting
- Interactive shell emulation after auth — out of scope, different feature
- Per-IP or adaptive delay tuning — keep it simple with global/per-protocol config

## Decisions

### 1. Config resolution: global default with per-protocol override

Follow the existing `RAN_<PROTO>_ADDR` pattern. New config fields on the Config struct with a resolution helper:

```
Config.MaxAuthRetries      int           // from RAN_MAX_AUTH_RETRIES, default 3
Config.AuthDelay           time.Duration // from RAN_AUTH_DELAY, default 0
Config.SSHTarpit           bool          // from RAN_SSH_TARPIT, default false
Config.SSHTarpitDuration   time.Duration // from RAN_SSH_TARPIT_DURATION, default 30s
Config.PerProto            map[string]ProtoConfig
```

`ProtoConfig` holds optional overrides (max auth retries, auth delay, session timeout). A helper `Config.ResolveMaxAuthRetries(proto string) int` checks per-proto first, falls back to global. Same pattern for AuthDelay and SessionTimeout.

**Alternative considered**: Separate struct per handler. Rejected — the `RAN_<PROTO>_*` env var pattern already exists for addresses and would be inconsistent if we handled these differently.

### 2. SSH outcome: authSeen flag in PasswordCallback closure

The PasswordCallback closure sets a `bool` flag when it fires. After `NewServerConn` returns an error, check the flag: if `authSeen == true`, outcome is `"completed"` (the honeypot did its job). If `authSeen == false`, it's a real handshake failure — classify based on error type (timeout vs error vs probe).

SSH `MaxAuthTries` in `gossh.ServerConfig` controls how many auth attempts the library allows before closing. Set it from `Config.ResolveMaxAuthRetries("ssh")` (default 6 for SSH). The PasswordCallback fires multiple times within a single `NewServerConn` call — no loop needed in our code.

**Alternative considered**: Wrapping the SSH library to intercept the error. Rejected — the `authSeen` flag is simpler and the library already supports `MaxAuthTries`.

### 3. Multi-auth loops for Telnet, MSSQL, SMB

Each handler wraps its auth logic in a for-loop bounded by `Config.ResolveMaxAuthRetries(proto)`. When `maxRetries == 0`, loop until timeout or client disconnect.

- **Telnet**: loop `{ prompt "Login:" → read → prompt "Password:" → read → "Login incorrect" }`, reset deadline after each attempt
- **MSSQL**: after prelogin exchange, loop `{ read Login7 → parse creds → send error response }`. Non-TDS first packets get outcome `"probe"` before the loop starts
- **SMB**: after Negotiate, loop `{ read Session Setup → parse NTLMSSP → send LOGON_FAILURE }`. Non-SMB connections get `"probe"`

Deadline is NOT reset per attempt — the session timeout is the outer bound. The auth delay eats into the timeout, which naturally caps how many attempts fit.

### 4. Escalating auth delay

Before sending each auth failure response, sleep `baseDelay × 2^attempt`, capped at `4 × baseDelay`. The delay is context-aware — if the session deadline fires during sleep, the handler returns cleanly with outcome `"timeout"`.

Implementation: a helper function `authSleep(ctx context.Context, baseDelay time.Duration, attempt int) error` that uses `time.NewTimer` + `select` on `ctx.Done()`. Shared across all handlers.

```
attempt 0: base × 1    (e.g. 2s)
attempt 1: base × 2    (e.g. 4s)
attempt 2: base × 4    (e.g. 8s)
attempt 3+: base × 4   (capped)
```

**Alternative considered**: Randomized delay to look more natural. Rejected for now — adds complexity, and real servers have fairly consistent auth delay.

### 5. SSH tarpit (endlessh-style)

Before starting the real SSH handshake, if `Config.SSHTarpit` is enabled, enter a drip phase:
1. Send random 32-byte lines (printable ASCII + `\r\n`) at 10-second intervals
2. Continue for `Config.SSHTarpitDuration` or until client disconnects
3. Then send the real `SSH-2.0-OpenSSH_9.6` banner and proceed with normal handshake

The SSH RFC allows arbitrary lines before the version string. Clients must wait for a line starting with `SSH-`. This is well-established (endlessh has 7k+ GitHub stars).

The tarpit phase writes directly to the raw `net.Conn` before handing it to `gossh.NewServerConn`. The session deadline covers both tarpit + auth phases combined — set from `Config.ResolveSessionTimeout("ssh")`.

Implementation: a helper `sshTarpit(ctx context.Context, conn net.Conn, duration time.Duration) error` that returns when duration elapses or context cancels.

### 6. Probe outcome classification

Handlers that parse binary protocols (MSSQL, SMB) set outcome to `"probe"` when the first bytes don't match the expected protocol magic:
- MSSQL: first packet type is not `0x12` (TDS prelogin) → `"probe"`
- SMB: first NetBIOS payload doesn't start with `0xFF SMB` or `0xFE SMB` → `"probe"`

For text-based protocols (Telnet) and SSH, scanner detection is less clear-cut, so we don't add `"probe"` there — their errors are genuine read failures.

The `"probe"` value is just a new label on the existing `ran_connections_total` counter — no metrics code changes needed.

## Risks / Trade-offs

**[Risk] Tarpit + auth delay could exceed session timeout** → The session deadline is the hard outer bound. `authSleep` and tarpit both respect `ctx.Done()`. If timeout is 30s and tarpit is 30s, zero auth attempts happen — operator must configure sensibly. Document that `SESSION_TIMEOUT > TARPIT_DURATION + (MAX_RETRIES × AUTH_DELAY cap)`.

**[Risk] Escalating delay holds server resources (goroutine + conn) longer** → Bounded by session timeout and max sessions. The limiter already enforces `RAN_MAX_SESSIONS` and `RAN_MAX_PER_IP`. Sleeping goroutines are cheap (~4KB stack).

**[Risk] Aggressive tarpit could be fingerprinted** → Real endlessh is widely deployed; botnets already handle it by timing out. The hybrid approach (tarpit then real SSH) means patient bots still donate credentials.

**[Risk] `MaxAuthTries=0` in golang.org/x/crypto/ssh means default (6), not unlimited** → Verify library behavior. If 0 means default, use a high sentinel value (e.g. 100) for "unlimited" in SSH specifically. Other protocols control their own loops and can use 0 directly.

## Open Questions

- Should per-protocol session timeout (`RAN_<PROTO>_SESSION_TIMEOUT`) be included in this change or deferred? It's listed in the proposal but adds config surface. Leaning toward including it since SSH tarpit needs a longer timeout to be useful.
