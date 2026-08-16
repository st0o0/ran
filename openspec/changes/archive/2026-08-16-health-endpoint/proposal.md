## Why

The current Docker healthcheck (`ran healthcheck`) does a blind TCP dial to the metrics port. It confirms the port is open but returns no diagnostic information — no version, no uptime, no trap list. When debugging a running container via `docker inspect` or compose logs, there is nothing actionable. Replacing the TCP dial with a proper HTTP `/healthz` endpoint gives structured health information at zero extra cost since the metrics HTTP server already exists.

## What Changes

- Add a `GET /healthz` endpoint to the existing metrics HTTP server that returns JSON with status, version, uptime, and the list of enabled traps.
- Track process start time so the endpoint can report uptime.
- Change the `ran healthcheck` subcommand from TCP dial to HTTP GET against `/healthz`, exit 0 on HTTP 200, exit 1 otherwise.
- No new ports, no new dependencies, no config changes.

## Capabilities

### New Capabilities
- `health-endpoint`: HTTP health endpoint on the metrics server returning structured JSON health status.

### Modified Capabilities
- `lifecycle`: The healthcheck subcommand changes from TCP dial to HTTP GET. The contract (exit 0 = healthy, exit 1 = unhealthy) stays the same.
- `container`: HEALTHCHECK directive gains `--start-period=15s` and `--timeout=10s`.

## Impact

- **Code**: `cmd/ran/main.go` (register `/healthz` handler, track start time), `cmd/ran/health.go` (HTTP GET instead of TCP dial).
- **Container**: Dockerfile HEALTHCHECK updated with `--start-period=45s` and `--timeout=10s`.
- **APIs**: New HTTP endpoint `GET /healthz` on the metrics address. Not a breaking change — additive only.
- **Dependencies**: None.
