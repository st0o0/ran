## Why

Several traps classify too coarsely or end too early, which costs signal or produces noise:

- `modbus` marks every parseable frame as `attack`; a harmless read counts like a write.
- `adb` ends after the AUTH token, so the `OPEN shell:` command that follows is never captured.
- `telnet` does no option negotiation: IAC bytes of Mirai-style clients leak into the username.
- `mysql`, `postgres` and `rdp` end after one attempt although brute-force clients retry.
- Scan detection counts distinct protocols only and ignores slow scanners and multi-port spread.

## What Changes

- `modbus`: read function codes (1 to 4) and device identification (43) are logged as `probe`-level fingerprinting; write codes (5, 6, 15, 16, 22, 23) are `attack`. Meta gains the start address and quantity.
- `adb`: after the AUTH token the trap reads the next packet; `AUTH` signature/public key and `OPEN` with `shell:`/`exec:` destinations are recorded (bounded) and answered with `CLSE`.
- `telnet`: IAC sequences are parsed and answered with `WONT`/`DONT`, never reach the username; the terminal type reply is logged.
- `mysql`, `postgres`, `rdp`: honor `RAN_MAX_AUTH_RETRIES` like `ssh`, `telnet`, `mssql` and `smb` (the README list of retry-capable traps changes).
- Scan detection additionally counts distinct destination ports of one source within the window (threshold documented, configurable later) in addition to distinct protocols.

## Capabilities

### Modified Capabilities

- `trap-modbus`, `trap-adb`, `trap-telnet`, `multi-auth`, `alert-classification`.

## Impact

- `modbus.go`, `adb.go`, `telnet.go`, `mysql.go`, `postgres.go`, `rdp.go`, `internal/alert/scan.go`, README (classification notes, retry list) and `trap-*` specs. `Known follow-ups` entries for modbus/adb in `AGENTS.md` are removed when this ships.

## Non-goals

- No shell emulation for telnet or adb (Icebox in `todo.md`).
- No change to the class names or to `RAN_BAN_ON` semantics.
- No UDP in scan detection (spoofable).
