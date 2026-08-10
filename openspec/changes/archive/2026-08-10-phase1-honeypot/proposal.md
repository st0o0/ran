## Why

Rán needs its core honeypot functionality — the actual Go binary that emulates network services, captures credentials, and logs everything as structured JSON. The CI/CD infrastructure is in place; now the application code needs to be built. Phase 1 covers the three most commonly probed protocols (SSH, HTTP, MySQL) plus the shared scaffold (config, metrics, logging, Dockerfile).

CrowdSec integration is intentionally deferred — the push LAPI approach is not the right fit; a log-based acquisition (CrowdSec reads Rán's JSON logs) is more native but needs its own design exploration.

## What Changes

- Add Go module with `cmd/ran/` entrypoint, config parsing, signal handling, healthcheck subcommand
- Add `internal/config/` with env-var parsing (bifrost-style `envReader` with `getenv` injection)
- Add `internal/trap/` with `Trap` interface and three implementations:
  - SSH trap (`crypto/ssh` — auto-generated host key, persist to `/data/` if available)
  - HTTP trap (`net/http` — fake login pages for `/admin`, `/wp-login.php`)
  - MySQL trap (raw `net.Conn` — wire protocol handshake with `mysql_clear_password` to capture plaintext credentials)
- Add `internal/metrics/` with Prometheus metrics registry
- Add connection limiting (`RAN_MAX_SESSIONS`, `RAN_MAX_PER_IP`) to protect against resource exhaustion
- Add multi-stage Dockerfile (Go builder → scratch, `<20MB`)
- Add structured JSON logging via `log/slog`
- Update README.md with usage documentation

## Capabilities

### New Capabilities
- `config`: Environment variable parsing with `RAN_` prefix, feature toggles, duration parsing, validation
- `trap-ssh`: SSH honeypot that captures credentials via `crypto/ssh` password callback
- `trap-http`: HTTP honeypot serving fake login pages, capturing POST form data
- `trap-mysql`: MySQL honeypot implementing auth handshake with `mysql_clear_password` for plaintext credential capture
- `metrics`: Prometheus metrics endpoint with connection, credential, and session counters/gauges/histograms
- `lifecycle`: Application entrypoint with signal handling, graceful shutdown, healthcheck subcommand, and connection limiting
- `container`: Multi-stage Dockerfile producing a minimal scratch-based image

### Modified Capabilities

_(none)_

## Impact

- New Go module at repo root (`go.mod`, `go.sum`)
- New source code in `cmd/ran/` and `internal/`
- New `Dockerfile` for container builds
- Updated `README.md`
- CI workflows (from repo-setup change) will activate once the Go module and Dockerfile exist
- Smoke test in ci.yml expects `ran` without args to exit code 1 — config parsing must enforce this
