## Context

The metrics HTTP server at `:9550` already serves `/metrics` for Prometheus. The `ran healthcheck` subcommand does a TCP dial against that port. This gives Docker a binary healthy/unhealthy signal but no structured diagnostics.

The process start time is not tracked anywhere. The version string lives in `main.version` (ldflags-injected) but is only accessible via the `ran version` subcommand, not programmatically from the HTTP server.

## Goals / Non-Goals

**Goals:**
- Expose structured health information (status, version, uptime, enabled traps) via HTTP on the existing metrics server.
- Make `ran healthcheck` consume this endpoint so Docker gets a proper HTTP-level check.

**Non-Goals:**
- Per-trap liveness probing (TCP-dialing each trap port). Traps bind once and stay open — if the process is alive, the traps are running.
- Kubernetes-style liveness/readiness split. A single `/healthz` is sufficient for Docker/compose.
- Adding new configuration options or ports.

## Decisions

### 1. Endpoint placement: metrics mux, not a separate server

The `/healthz` handler registers on the same `http.ServeMux` that serves `/metrics`. No new goroutine, no new port.

*Alternative: dedicated health port.* Rejected — adds config complexity for zero benefit. The metrics port is already exposed and non-sensitive.

### 2. Response shape

```json
{"status":"ok","version":"0.3.0","uptime":"2h15m3s","traps":["ssh","http","rdp"]}
```

- `status`: always `"ok"` (if the server can respond, it's healthy).
- `version`: build-injected version string.
- `uptime`: `time.Since(startTime).Truncate(time.Second).String()`.
- `traps`: the list from `cfg.EnabledTraps()`, gives operators visibility into what's running.

Always returns HTTP 200. If the server can't respond, Docker sees the timeout/connection failure and marks unhealthy.

*Alternative: return 503 on degraded state.* Rejected — there is no meaningful degraded state to detect without per-trap probing (non-goal).

### 3. Passing state to the handler

The handler needs: version (string), start time (time.Time), trap names ([]string). These are all available at init time in `main()`. Pass them via a closure or a small struct — no global state, no shared mutable state.

### 4. Healthcheck subcommand: HTTP GET

`ran healthcheck` changes from `net.DialTimeout` to `http.Get("http://<metricsAddr>/healthz")`. When `metricsAddr` starts with `:` (no host, e.g. `:9550`), prefix with `localhost` to form a valid URL. Exit 0 on HTTP 200, exit 1 on any error. The response body is discarded — the subcommand is for Docker, not for humans (humans can curl `/healthz` directly).

## Risks / Trade-offs

- **[Metrics server down = unhealthy]** → This is the same as today. If the metrics server fails to start, the process exits. Acceptable.
- **[No per-trap health]** → A single trap silently dying would not be detected. Mitigated by the fact that TCP listeners in Go don't silently die, and `run()` already exits if all traps fail at startup.
- **[Uptime resets on restart]** → Expected behavior for a stateless process.
