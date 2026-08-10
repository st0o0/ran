# rán

[![CI](https://github.com/st0o0/ran/actions/workflows/ci.yml/badge.svg)](https://github.com/st0o0/ran/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/st0o0/ran?sort=semver)](https://github.com/st0o0/ran/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-st0o0%2Fran-2496ED?logo=docker&logoColor=white)](https://github.com/st0o0/ran/pkgs/container/ran)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

A single-binary honeypot that emulates **27 network services** — from SSH and
RDP to Modbus and MQTT — captures credentials, commands, and payloads as
structured JSON, and pushes ban decisions to CrowdSec. Pure Go, no external
dependencies, **~8 MB scratch image**.

Named after the Norse goddess who catches sailors in her net.

```yaml
services:
  ran:
    image: ghcr.io/st0o0/ran:latest
    restart: unless-stopped
    environment:
      RAN_TRAPS: ssh,http,ftp,telnet,redis,rdp,smb
      RAN_CROWDSEC: "on"
      RAN_CROWDSEC_URL: http://crowdsec:8080
      RAN_CROWDSEC_API_KEY: ${CROWDSEC_KEY}
    ports:
      - "2222:2222"   # SSH
      - "8081:8081"   # HTTP
      - "21:21"       # FTP
      - "23:23"       # Telnet
      - "6379:6379"   # Redis
      - "3389:3389"   # RDP
      - "445:445"     # SMB
      - "9550:9550"   # Prometheus metrics
```

## Features

- **27 protocol traps, one binary.** Credential capture for SSH, FTP, Telnet,
  SMTP, MySQL, PostgreSQL, MSSQL, RDP, VNC, SMB, LDAP, and more. Command logging
  for Redis, Memcached, IRC. Payload inspection for DNS, SNMP, Modbus, MQTT.
- **CrowdSec-native.** Every credential capture pushes a self-contained ban
  decision to CrowdSec's LAPI — bouncers (Caddy, Nginx, iptables) enforce it
  automatically. No local scenario needed.
- **Structured JSON logging.** Every connection, auth attempt, command, and
  payload is a single JSON line to stdout with session ID, source IP, protocol,
  and action — ready for Loki, Elasticsearch, or any log pipeline.
- **Pick exactly what you need.** Enable traps with a comma-separated list
  (`RAN_TRAPS=ssh,rdp,smb`). Each trap has a sensible default port,
  overridable per-trap.
- **Rate-limited and safe.** Per-IP and global session limits prevent resource
  exhaustion. UDP traps drop amplification probes (NTP monlist, DNS ANY).
  Session timeouts enforce cleanup.
- **Tiny, static, scratch.** Single Go binary, no CGO, no shell, no coreutils.
  ~8 MB image for `linux/amd64` and `linux/arm64`.

## Why

| | T-Pot | qeeqbox/honeypots | **rán** |
|---|:---:|:---:|:---:|
| Single binary / container | ❌ 31 containers | ⚠️ Python + deps | ✅ |
| Protocol coverage | ✅ 31 honeypots | ✅ 30 protocols | ✅ 27 protocols |
| Resource footprint | ❌ 8+ GB RAM | ⚠️ ~500 MB | ✅ ~20 MB |
| CrowdSec integration | ⚠️ via log parser | ❌ | ✅ native LAPI push |
| Selective trap enabling | ⚠️ edition-based | ✅ | ✅ |
| No external dependencies | ❌ Docker Compose stack | ❌ Python, pip | ✅ static Go binary |
| Prometheus metrics | ✅ via ELK | ❌ | ✅ native |

- **T-Pot** is a full honeypot platform — 31 Docker containers, ELK stack,
  Kibana dashboards, 8+ GB RAM minimum. Great for dedicated honeypot servers,
  heavy for a side deployment.
- **qeeqbox/honeypots** covers 30 protocols in Python. Solid protocol breadth
  but requires a Python runtime, pip dependencies, and has no built-in
  threat-intelligence integration.

## Quick start

1. Choose your traps. Start small — `ssh,http,ftp` covers the most-scanned ports.
2. Run the container:

```bash
docker run --rm \
  -e RAN_TRAPS=ssh,http,ftp \
  -p 2222:2222 -p 8081:8081 -p 21:21 -p 9550:9550 \
  ghcr.io/st0o0/ran:latest
```

3. Watch credentials roll in:

```bash
docker logs -f ran
```

Prometheus metrics are at `:9550/metrics`.

## How it works

```
attacker connects ──▶ protocol handshake ──▶ credential / command / payload capture
        │                       │                            │
        │                       │                            ▼
        │                       │                    structured JSON → stdout
        │                       │                            │
        ▼                       ▼                            ▼
   rate limiter           plausible error            CrowdSec LAPI alert
  (per-IP + global)       (access denied)            (self-contained ban)
                                                           │
                                                           ▼
                                                    bouncers enforce
                                                  (Caddy, nginx, iptables)
```

Every trap emulates just enough protocol to complete the handshake, capture
the interesting data, and return a plausible error. No interactive sessions,
no filesystem emulation, no query execution — minimal attack surface on the
honeypot itself.

## Traps

### Remote access

| Name | Port | Captures |
|---|---|---|
| `ssh` | `:2222` | Credentials — OpenSSH banner, password auth |
| `rdp` | `:3389` | Username — X.224 cookie extraction |
| `vnc` | `:5900` | Auth challenge/response — VNC Authentication |
| `telnet` | `:23` | Credentials — login/password prompts |

### Web & proxy

| Name | Port | Captures |
|---|---|---|
| `http` | `:8081` | Credentials — WordPress + admin login pages |
| `httpproxy` | `:8080` | Proxy targets + Proxy-Authorization credentials |
| `elasticsearch` | `:9200` | API requests — fake cluster responses |

### Databases

| Name | Port | Captures |
|---|---|---|
| `mysql` | `:3307` | Credentials — wire protocol, cleartext password |
| `postgres` | `:5432` | Credentials — cleartext password auth |
| `mssql` | `:1433` | Credentials — TDS Login7 with password decode |
| `oracle` | `:1521` | Credentials — TNS connect descriptor |
| `redis` | `:6379` | AUTH credentials + RESP command logging |
| `memcached` | `:11211` | Command logging — text protocol |

### Mail

| Name | Port | Captures |
|---|---|---|
| `smtp` | `:25` | Credentials — AUTH LOGIN / PLAIN |
| `pop3` | `:110` | Credentials — USER / PASS |
| `imap` | `:143` | Credentials — LOGIN command |

### Directory & network

| Name | Port | Captures |
|---|---|---|
| `ldap` | `:389` | Credentials — simple bind DN + password |
| `smb` | `:445` | Credentials — NTLMSSP domain\user + workstation |
| `socks5` | `:1080` | Credentials + proxy target addresses |
| `irc` | `:6667` | PASS credentials + NICK/USER/JOIN commands |

### IoT & industrial

| Name | Port | Captures |
|---|---|---|
| `mqtt` | `:1883` | Credentials — CONNECT client ID + user/pass |
| `modbus` | `:502` | ICS payloads — function codes + registers |

### UDP

| Name | Port | Captures |
|---|---|---|
| `dns` | `:53` | Query domains + types — responds REFUSED |
| `snmp` | `:161` | Community strings — v1/v2c GetRequest |
| `sip` | `:5060` | SIP URIs + digest credentials |
| `ntp` | `:123` | Request metadata — drops monlist amplification |

## Configuration

### Trap selection

| Variable | Default | Purpose |
|---|---|---|
| `RAN_TRAPS` | | Comma-separated list of traps to enable |
| `RAN_<PROTO>_ADDR` | *(see traps table)* | Override listen address for any trap |

> Legacy variables `RAN_SSH=on`, `RAN_HTTP=on`, `RAN_MYSQL=on` still work but
> `RAN_TRAPS` takes precedence when set.

### Logging

| Variable | Default | Purpose |
|---|---|---|
| `RAN_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `RAN_LOG_FORMAT` | `json` | Log format: json, text |

### Limits

| Variable | Default | Purpose |
|---|---|---|
| `RAN_SESSION_TIMEOUT` | `30s` | Max session duration (Go duration) |
| `RAN_MAX_SESSIONS` | `500` | Global concurrent session limit |
| `RAN_MAX_PER_IP` | `10` | Per-IP concurrent session limit |

### Metrics

| Variable | Default | Purpose |
|---|---|---|
| `RAN_METRICS_ADDR` | `:9550` | Prometheus metrics listen address |

Exposed metrics:

- `ran_connections_total{protocol}` — connection counter
- `ran_credentials_captured_total{protocol}` — credential capture counter
- `ran_active_sessions{protocol}` — active session gauge
- `ran_session_duration_seconds{protocol}` — session duration histogram
- `ran_crowdsec_alerts_total{protocol,status}` — CrowdSec alert push counter

### CrowdSec

| Variable | Default | Purpose |
|---|---|---|
| `RAN_CROWDSEC` | `off` | Enable CrowdSec LAPI alerting |
| `RAN_CROWDSEC_URL` | | CrowdSec LAPI URL (required when enabled) |
| `RAN_CROWDSEC_API_KEY` | | CrowdSec bouncer API key (required when enabled) |
| `RAN_CROWDSEC_BAN_DURATION` | `4h` | Ban duration (`0` = permanent) |

Scenario names follow the pattern `custom/ran-<protocol>-trap`. Each alert
includes a self-contained ban decision — CrowdSec forwards it directly to
bouncers without needing a local scenario.

## Log output

Structured JSON to stdout, one line per event:

```json
{
  "time": "2025-01-15T14:23:01Z",
  "level": "INFO",
  "msg": "auth_attempt",
  "protocol": "ssh",
  "session_id": "a1b2c3d4",
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "action": "auth_attempt",
  "username": "root",
  "password": "admin123"
}
```

Actions: `connect`, `auth_attempt`, `command`, `payload`, `disconnect`.

## Troubleshooting

- **`at least one trap must be enabled`** — set `RAN_TRAPS` or at least one
  `RAN_<PROTO>=on` variable.
- **Port already in use** — another service is on the default port. Override
  with `RAN_<PROTO>_ADDR=:<port>`.
- **CrowdSec alerts not arriving** — verify `RAN_CROWDSEC_URL` is reachable
  from the container and the API key is a valid bouncer key.
- **UDP traps not receiving packets** — Docker needs explicit UDP port mapping:
  `-p 53:53/udp`, not just `-p 53:53`.
- **High connection volume causing drops** — increase `RAN_MAX_SESSIONS` and
  `RAN_MAX_PER_IP`, or enable only the traps you need.

## Development

```bash
# tests
go test ./...

# vet + lint (golangci-lint v2)
go vet ./...
golangci-lint run

# Dockerfile lint
docker run --rm -i hadolint/hadolint < Dockerfile

# build
docker build -t ran:dev .
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
releases and the GHCR image are cut automatically by release-please.

## Image

- Registry: `ghcr.io/st0o0/ran`
- Tags: `latest`, `MAJOR.MINOR`, and the exact `MAJOR.MINOR.PATCH` per release.
- Architectures: `linux/amd64`, `linux/arm64`.

## License

MIT (see [`LICENSE.md`](LICENSE.md)). rán is a pure-Go static binary; the built
image bundles no third-party GPL binaries. Its Go module dependencies are
permissively licensed (MIT/BSD); see `go.sum`.
