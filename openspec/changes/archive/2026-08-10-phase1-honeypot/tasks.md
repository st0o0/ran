## 1. Project Scaffold

- [x] 1.1 Initialize Go module (`go mod init github.com/st0o0/ran`) with latest stable Go version
- [x] 1.2 Create `internal/config/config.go` with `envReader` struct (bifrost-style `getenv` injection), `Load` function, and all `RAN_*` env vars with defaults
- [x] 1.3 Create `internal/config/config_test.go` with tests for defaults, all toggles, duration parsing, validation (no traps enabled → error), and invalid values
- [x] 1.4 Create `internal/metrics/metrics.go` with Prometheus registry: `ran_connections_total`, `ran_credentials_captured_total`, `ran_active_sessions`, `ran_session_duration_seconds`
- [x] 1.5 Create `cmd/ran/main.go` with config loading, slog setup (level + format), metrics HTTP server, signal handling (SIGTERM/SIGINT), and graceful shutdown
- [x] 1.6 Create `cmd/ran/health.go` with `healthcheck` subcommand (TCP dial to metrics addr, exit 0/1)
- [x] 1.7 Create `cmd/ran/version.go` with `version` subcommand (print ldflags-injected version, inline in main.go switch)

## 2. Trap Infrastructure

- [x] 2.1 Create `internal/trap/trap.go` with `Trap` interface (`Start(ctx) error`, `Stop(ctx) error`), session struct (UUID, protocol, source IP/port, start time), and shared session logging helpers
- [x] 2.2 Create `internal/trap/limiter.go` with connection limiter (global max sessions + per-IP max, goroutine-safe counters, `Acquire`/`Release` methods)
- [x] 2.3 Create `internal/trap/limiter_test.go` with tests for global limit, per-IP limit, release, and concurrent access

## 3. SSH Trap

- [x] 3.1 Create `internal/trap/ssh.go` with SSH trap: Ed25519 host key generation/loading, `crypto/ssh` ServerConfig with password callback, session timeout, banner (`SSH-2.0-OpenSSH_9.6`), credential logging
- [x] 3.2 Create `internal/trap/ssh_test.go` with tests: host key generation, password callback captures credentials, session timeout, log output verification

## 4. HTTP Trap

- [x] 4.1 Create `internal/trap/http.go` with HTTP trap: `net/http` server, login page handlers (`/admin`, `/wp-login.php`, `/` catch-all), POST credential extraction (username/password field variants), realistic HTML responses, session logging
- [x] 4.2 Create `internal/trap/http_test.go` with tests: GET returns login page, POST captures credentials, multiple field name variants, response headers

## 5. MySQL Trap

- [x] 5.1 Create `internal/trap/mysql.go` with MySQL trap: raw `net.Conn` listener, wire protocol (Initial Handshake with `mysql_clear_password`, Handshake Response parsing, ERR packet), credential extraction, session logging
- [x] 5.2 Create `internal/trap/mysql_test.go` with tests: greeting packet encoding, handshake response decoding, plaintext credential extraction, timeout on stalled handshake

## 6. Integration & Wiring

- [x] 6.1 Wire all traps into `main.go`: start enabled traps as goroutines, pass config/metrics/limiter, graceful shutdown drains all
- [x] 6.2 Create integration test that starts each trap, connects to it, verifies structured log output contains expected fields

## 7. Container

- [x] 7.1 Create `Dockerfile` with multi-stage build (golang-alpine → scratch), `CGO_ENABLED=0`, `-trimpath`, ldflags version injection, HEALTHCHECK
- [x] 7.2 Update `README.md` with usage documentation: env vars, deployment, compose example reference

## 8. End-to-End Test

- [x] 8.1 Create `tests/e2e/run.sh` that builds the image, starts the container with all traps enabled, connects to each trap, and verifies log output
