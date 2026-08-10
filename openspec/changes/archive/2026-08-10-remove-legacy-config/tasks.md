## 1. Config struct and loader

- [x] 1.1 Remove legacy fields from Config struct: `SSH`, `HTTP`, `MySQL`, `SSHAddr`, `HTTPAddr`, `MySQLAddr`
- [x] 1.2 Add `SSHHostKeyPath string` field to Config struct
- [x] 1.3 Load `RAN_SSH_HOST_KEY_PATH` in `Load()` with default `/data/ssh_host_key`
- [x] 1.4 Remove legacy env var parsing block (`RAN_SSH`, `RAN_HTTP`, `RAN_MYSQL` booleans) from `Load()`
- [x] 1.5 Remove legacy sync code at end of `Load()` (lines setting `c.SSH`, `c.HTTP`, `c.MySQL`, `c.SSHAddr`, `c.HTTPAddr`, `c.MySQLAddr`)
- [x] 1.6 Update "no traps enabled" error message to reference only `RAN_TRAPS`

## 2. Trap migration

- [x] 2.1 Migrate `ssh.go`: replace `t.cfg.SSHAddr` with `t.cfg.TrapAddr("ssh")`
- [x] 2.2 Migrate `ssh.go`: replace hardcoded `sshHostKeyPath` constant with `t.cfg.SSHHostKeyPath`
- [x] 2.3 Migrate `http.go`: replace `cfg.HTTPAddr` with `cfg.TrapAddr("http")`
- [x] 2.4 Migrate `mysql.go`: replace `t.cfg.MySQLAddr` with `t.cfg.TrapAddr("mysql")`

## 3. Tests

- [x] 3.1 Update `config_test.go`: remove tests for legacy toggle env vars, add test for `SSHHostKeyPath`
- [x] 3.2 Update `config_test.go`: remove assertions on legacy fields (`SSH`, `HTTP`, `MySQL`, `SSHAddr`, `HTTPAddr`, `MySQLAddr`)
- [x] 3.3 Update trap test files referencing legacy config fields to use generic patterns
- [x] 3.4 Run `go build ./...` and `go test ./...` to verify clean compile and passing tests
