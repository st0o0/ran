## Context

Rán is a Go honeypot container for a homelab proxy stack (Caddy L4 + CrowdSec + Bifrost/WireGuard). It emulates common network services to capture attacker credentials and connection metadata. Phase 1 covers SSH, HTTP, and MySQL traps. Rán follows the same conventions as bifrost and eir (env-var config, slog logging, scratch Docker image, Prometheus metrics).

The deployment model is `network_mode: service:bifrost` — Rán shares bifrost's network namespace, so Caddy L4 routes trap ports to localhost.

## Goals / Non-Goals

**Goals:**
- Capture credentials from SSH, HTTP, and MySQL probes as structured JSON logs
- Expose Prometheus metrics for connection tracking
- Run as a minimal scratch-based container (<20MB)
- Graceful shutdown, healthcheck subcommand, resource-safe under brute-force load

**Non-Goals:**
- CrowdSec integration (deferred — push LAPI is wrong approach, log-based acquisition needs separate design)
- Full protocol emulation beyond credential capture
- TLS on trap ports
- Web UI, database, config files
- Phase 2 protocols (Redis, FTP, SMTP)

## Decisions

### 1. Config: bifrost-style envReader with getenv injection
Use bifrost's `envReader` struct pattern with `Load(getenv func(string) string)`. This gives typed helpers (`str`, `intMin`, `boolean`, `duration`) with accumulated error reporting and full testability without setting real env vars. Duration fields use Go `time.ParseDuration` (eir-style, e.g. `"30s"`) rather than bifrost's integer-seconds.

### 2. SSH host key: auto-generate, optionally persist
Generate an Ed25519 host key at startup. If `/data/ssh_host_key` exists or `/data/` is writable, persist there for consistent fingerprint across restarts. Otherwise ephemeral. No env var needed — purely automatic. For a honeypot, ephemeral keys are fine; persistence is a convenience, not a requirement.

### 3. MySQL: advertise mysql_clear_password
The MySQL trap advertises `mysql_clear_password` as the auth plugin in the greeting packet. Most automated scanners/brute-forcers comply and send plaintext credentials. This gives us actual passwords to log, not just hashed challenge-responses. The trap implements exactly 3 wire protocol packets: Initial Handshake → Handshake Response → ERR (Access Denied).

### 4. Connection limiting
Two knobs to prevent resource exhaustion under brute-force:
- `RAN_MAX_SESSIONS=500` — global maximum concurrent sessions across all traps
- `RAN_MAX_PER_IP=10` — per-IP concurrent session limit

Excess connections are accepted, logged (at warn level), and immediately closed. This is simpler and more predictable than rate-limiting, and protects the 128MB memory constraint. The limiter lives in shared trap infrastructure, not per-trap.

### 5. Country label removed from metrics
`ran_connections_total{protocol}` has no `country` label. GeoIP enrichment happens in Alloy/Loki where the GeoIP database already exists. Rán logs the source IP; the observability stack enriches it.

### 6. Trap interface
```go
type Trap interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
}
```
Each trap runs as a goroutine. `Start` blocks until `ctx` is cancelled. `Stop` performs graceful drain (close listener, wait for active sessions up to a timeout). Main starts all enabled traps, `signal.NotifyContext` cancels on SIGTERM/SIGINT.

### 7. Session model
Every connection gets a `session_id` (UUID v4). All log entries for that connection include the session ID for correlation. A session tracks: protocol, source IP/port, start time, credentials captured, and action sequence.

### 8. Logging structure
Every trap event is a structured slog log line:
```json
{"time":"...","level":"INFO","msg":"auth_attempt","protocol":"ssh","session_id":"...","source_ip":"...","source_port":12345,"username":"root","password":"admin123"}
```
Actions: `connect`, `auth_attempt`, `command` (HTTP POST path), `disconnect`.

### 9. Dockerfile: scratch, CGO_ENABLED=0
`crypto/ssh` is pure Go (`golang.org/x/crypto/ssh`), no CGO needed. Same pattern as bifrost/eir: `golang:<version>-alpine` build stage → `scratch` runtime. Version injected via `-ldflags -X main.version=${VERSION}`. Healthcheck: `HEALTHCHECK CMD ["/ran", "healthcheck"]`.

### 10. Healthcheck subcommand
`ran healthcheck` exits 0 if the metrics HTTP server responds (simple TCP dial to metrics addr). This confirms the process is alive and accepting connections. No protocol-specific health checking — if metrics is up, the process is running.

## Risks / Trade-offs

- **mysql_clear_password may not work with all clients** → Most brute-force tools comply; sophisticated scanners may refuse. This is acceptable — we capture what we can, and the connection attempt itself is still logged.
- **Ephemeral SSH keys mean MITM warnings on repeat connections** → Irrelevant for a honeypot; attackers don't verify host keys.
- **No CrowdSec in Phase 1** → Attackers are not auto-banned until CrowdSec integration is added. Acceptable for initial deployment since CrowdSec is already in the stack and can be configured separately to read Rán's logs.
- **128MB memory with 500 max sessions** → ~256KB per goroutine stack = ~128MB worst case for goroutines alone. In practice sessions are short-lived (30s timeout), so steady-state is much lower. Monitor in Grafana.

## Open Questions

- CrowdSec integration approach: log-based acquisition (CrowdSec reads Rán's stdout) vs. custom API. Deferred to a separate exploration.
