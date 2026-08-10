# Rán

Lightweight Go honeypot container. Emulates common network services (SSH, HTTP,
MySQL), captures credentials, and logs everything as structured JSON.

Named after the Norse goddess who traps sailors with her net.

## Quick start

```bash
docker run --rm \
  -e RAN_SSH=on \
  -e RAN_HTTP=on \
  -e RAN_MYSQL=on \
  -p 2222:2222 -p 8081:8081 -p 3307:3307 -p 9550:9550 \
  ghcr.io/st0o0/ran:latest
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `RAN_SSH` | `off` | Enable SSH trap |
| `RAN_HTTP` | `off` | Enable HTTP trap |
| `RAN_MYSQL` | `off` | Enable MySQL trap |
| `RAN_SSH_ADDR` | `:2222` | SSH listen address |
| `RAN_HTTP_ADDR` | `:8081` | HTTP listen address |
| `RAN_MYSQL_ADDR` | `:3307` | MySQL listen address |
| `RAN_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `RAN_LOG_FORMAT` | `json` | Log format: json, text |
| `RAN_METRICS_ADDR` | `:9550` | Prometheus metrics listen address |
| `RAN_SESSION_TIMEOUT` | `30s` | Max session duration (Go duration) |
| `RAN_MAX_SESSIONS` | `500` | Global concurrent session limit |
| `RAN_MAX_PER_IP` | `10` | Per-IP concurrent session limit |
| `RAN_CROWDSEC` | `off` | Enable CrowdSec LAPI alerting |
| `RAN_CROWDSEC_URL` | | CrowdSec LAPI URL (required when enabled) |
| `RAN_CROWDSEC_API_KEY` | | CrowdSec API key (required when enabled) |
| `RAN_CROWDSEC_BAN_DURATION` | `4h` | Ban duration (`0` = permanent) |

At least one trap must be enabled.

## Traps

**SSH** (`:2222`) — Presents an OpenSSH banner, accepts password auth attempts,
captures username/password, returns access denied.

**HTTP** (`:8081`) — Serves realistic login pages on `/admin` and `/wp-login.php`.
Captures POST form credentials.

**MySQL** (`:3307`) — Implements the MySQL wire protocol handshake with
`mysql_clear_password` to capture plaintext credentials.

## Metrics

Prometheus metrics on `RAN_METRICS_ADDR`:

- `ran_connections_total{protocol}` — connection counter
- `ran_credentials_captured_total{protocol}` — credential capture counter
- `ran_active_sessions{protocol}` — active session gauge
- `ran_session_duration_seconds{protocol}` — session duration histogram
- `ran_crowdsec_alerts_total{protocol,status}` — CrowdSec alert push counter

## CrowdSec integration

Rán can push alerts to CrowdSec's Local API on every credential capture. Each
alert includes a self-contained ban decision, so CrowdSec forwards it directly
to bouncers (e.g. Caddy bouncer) without needing a local scenario.

Scenario names per protocol: `custom/ran-ssh-trap`, `custom/ran-http-trap`,
`custom/ran-mysql-trap`.

```bash
docker run --rm \
  -e RAN_SSH=on \
  -e RAN_CROWDSEC=on \
  -e RAN_CROWDSEC_URL=http://crowdsec:8080 \
  -e RAN_CROWDSEC_API_KEY=your-api-key \
  -e RAN_CROWDSEC_BAN_DURATION=4h \
  -p 2222:2222 -p 9550:9550 \
  ghcr.io/st0o0/ran:latest
```

## Log output

Structured JSON to stdout:

```json
{"time":"...","level":"INFO","msg":"auth_attempt","protocol":"ssh","session_id":"...","source_ip":"1.2.3.4","source_port":54321,"action":"auth_attempt","username":"root","password":"admin123"}
```

## License

[MIT](LICENSE.md)
