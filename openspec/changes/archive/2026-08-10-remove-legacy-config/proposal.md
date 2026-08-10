## Why

The Config struct carries dual addressing for SSH, HTTP, and MySQL: legacy per-trap bool/addr fields (`SSH`, `HTTP`, `MySQL`, `SSHAddr`, `HTTPAddr`, `MySQLAddr`) alongside the generic `Traps`/`Addrs`/`TrapAddr()` system that all 24 newer traps already use. This duplication adds maintenance burden, makes the config harder to reason about, and forces `Load()` to include sync code that keeps both systems in lockstep. Cleaning this up completes the migration started when the generic trap system was introduced.

## What Changes

- **BREAKING**: Remove legacy Config fields: `SSH`, `HTTP`, `MySQL`, `SSHAddr`, `HTTPAddr`, `MySQLAddr`
- **BREAKING**: Remove legacy env var parsing for `RAN_SSH`, `RAN_HTTP`, `RAN_MYSQL` toggle booleans
- Remove legacy sync code at end of `Load()` (lines 151-185)
- Migrate `ssh.go` from `t.cfg.SSHAddr` to `t.cfg.TrapAddr("ssh")`
- Migrate `http.go` from `cfg.HTTPAddr` to `cfg.TrapAddr("http")`
- Migrate `mysql.go` from `t.cfg.MySQLAddr` to `t.cfg.TrapAddr("mysql")`
- Add `SSHHostKeyPath` config field with env var `RAN_SSH_HOST_KEY_PATH` (default `/data/ssh_host_key`)
- Replace hardcoded `sshHostKeyPath` constant in `ssh.go:23` with `t.cfg.SSHHostKeyPath`
- Update all affected tests to use generic config patterns

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `config`: Remove legacy per-trap fields and env vars; add `SSHHostKeyPath` field; simplify `Load()` to only use `RAN_TRAPS` for trap enabling

## Impact

- **Config struct**: 6 fields removed, 1 field added
- **Config loading**: `RAN_SSH`/`RAN_HTTP`/`RAN_MYSQL` env vars no longer recognized (users must use `RAN_TRAPS`)
- **Trap code**: `ssh.go`, `http.go`, `mysql.go` updated to use `TrapAddr()`
- **Tests**: `config_test.go` and any trap tests referencing legacy fields
- **Deployments**: Existing deployments using `RAN_SSH=on` must switch to `RAN_TRAPS=ssh,...`
