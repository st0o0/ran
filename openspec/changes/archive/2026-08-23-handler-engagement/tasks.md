## 1. Config Layer

- [x] 1.1 Add `MaxAuthRetries`, `AuthDelay`, `SSHTarpit`, `SSHTarpitDuration` fields and per-protocol override map to Config struct (`internal/config/config.go`)
- [x] 1.2 Parse new env vars: `RAN_MAX_AUTH_RETRIES`, `RAN_AUTH_DELAY`, `RAN_SSH_TARPIT`, `RAN_SSH_TARPIT_DURATION`, `RAN_<PROTO>_MAX_AUTH_RETRIES`, `RAN_<PROTO>_AUTH_DELAY`, `RAN_<PROTO>_SESSION_TIMEOUT`
- [x] 1.3 Implement `ResolveMaxAuthRetries(proto)`, `ResolveAuthDelay(proto)`, `ResolveSessionTimeout(proto)` methods
- [x] 1.4 Add config tests for new env vars: defaults, overrides, invalid values, unlimited (0)

## 2. Shared Helpers

- [x] 2.1 Add `authSleep(ctx, baseDelay, attempt) error` helper to `internal/trap/trap.go` — escalating delay with 4× cap, context-aware
- [x] 2.2 Add `sshTarpit(ctx, conn, duration) error` helper to `internal/trap/ssh.go` — random line drip at 10s intervals
- [x] 2.3 Add tests for `authSleep`: escalation math, cap at 4× base, context cancellation
- [x] 2.4 Add tests for `sshTarpit`: line format, interval, duration limit, client disconnect, lines don't start with `SSH-`

## 3. SSH Handler

- [x] 3.1 Add `authSeen` flag in PasswordCallback closure; set outcome to `"completed"` when `authSeen && NewServerConn fails`
- [x] 3.2 Set `ServerConfig.MaxAuthTries` from `cfg.ResolveMaxAuthRetries("ssh")`
- [x] 3.3 Integrate auth delay in PasswordCallback using `authSleep`
- [x] 3.4 Integrate tarpit phase before `NewServerConn` when `cfg.SSHTarpit` is enabled
- [x] 3.5 Use `cfg.ResolveSessionTimeout("ssh")` for session deadline
- [x] 3.6 Update SSH tests: multi-auth flow, outcome fix (completed vs error), tarpit phase, auth delay

## 4. Telnet Handler

- [x] 4.1 Wrap login/password prompt in retry loop bounded by `cfg.ResolveMaxAuthRetries("telnet")`
- [x] 4.2 Add auth delay via `authSleep` before "Login incorrect" response
- [x] 4.3 Use `cfg.ResolveSessionTimeout("telnet")` for session deadline
- [x] 4.4 Update Telnet tests: multi-attempt flow, delay behavior, timeout during retry

## 5. MSSQL Handler

- [x] 5.1 Classify non-TDS first packets (byte != 0x12, invalid length) as outcome `"probe"` instead of `"error"`
- [x] 5.2 Wrap Login7 read/respond in retry loop after prelogin handshake, bounded by `cfg.ResolveMaxAuthRetries("mssql")`
- [x] 5.3 Add auth delay via `authSleep` before TDS error response
- [x] 5.4 Use `cfg.ResolveSessionTimeout("mssql")` for session deadline
- [x] 5.5 Update MSSQL tests: multi-login flow, probe outcome for scanners, delay behavior

## 6. SMB Handler

- [x] 6.1 Classify non-SMB first messages (no 0xFF/0xFE SMB header) as outcome `"probe"`
- [x] 6.2 Wrap Session Setup handling in retry loop after Negotiate, bounded by `cfg.ResolveMaxAuthRetries("smb")`
- [x] 6.3 Add auth delay via `authSleep` before STATUS_LOGON_FAILURE response
- [x] 6.4 Use `cfg.ResolveSessionTimeout("smb")` for session deadline
- [x] 6.5 Update SMB tests: multi-session-setup flow, probe outcome, delay behavior

## 7. Integration & Validation

- [x] 7.1 Run full test suite, fix any regressions in unmodified handlers
- [x] 7.2 Run `golangci-lint` and fix any findings
- [x] 7.3 Verify metrics: `ran_connections_total` emits `probe` outcome label correctly
