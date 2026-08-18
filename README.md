# rán

[![CI](https://github.com/st0o0/ran/actions/workflows/ci.yml/badge.svg)](https://github.com/st0o0/ran/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/st0o0/ran?sort=semver)](https://github.com/st0o0/ran/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-st0o0%2Fran-2496ED?logo=docker&logoColor=white)](https://github.com/st0o0/ran/pkgs/container/ran)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

Single-binary honeypot written in Go. Emulates 29 network services (SSH, RDP,
Modbus, MQTT, …), captures credentials and payloads as structured JSON, and
pushes ban decisions to CrowdSec. No external dependencies, ~8 MB scratch image.

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
      RAN_CROWDSEC_MACHINE_ID: ran-honeypot
      RAN_CROWDSEC_PASSWORD: ${CROWDSEC_PASSWORD}
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

## Why rán?

There are already good honeypots out there. The reason I built rán:

- **T-Pot** is excellent if you have a dedicated server — but it's 31 Docker
  containers, an ELK stack, and 8+ GB RAM. Way too heavy for running alongside
  production services.
- **qeeqbox/honeypots** has great protocol coverage in Python, but it needs a
  Python runtime and pip, and doesn't integrate with CrowdSec.

rán does one thing: catch probes, log them, ban the source. Single static Go
binary, no shell, no runtime, just protocol stubs and a CrowdSec LAPI client.

| | T-Pot | qeeqbox/honeypots | rán |
|---|:---:|:---:|:---:|
| Single binary / container | 31 containers | Python + deps | yes |
| Protocol coverage | 31 honeypots | 30 protocols | 29 protocols |
| RAM | 8+ GB | ~500 MB | ~20 MB |
| CrowdSec | via log parser | no | native LAPI push |
| Selective traps | edition-based | yes | yes |
| External deps | Docker Compose stack | Python, pip | none (static binary) |
| Prometheus metrics | via ELK | no | native |

## Quick start

Pick your traps, start the container:

```bash
docker run --rm \
  -e RAN_TRAPS=ssh,http,ftp \
  -p 2222:2222 -p 8081:8081 -p 21:21 -p 9550:9550 \
  ghcr.io/st0o0/ran:latest
```

Watch the logs with `docker logs -f ran`. Prometheus metrics are at `:9550/metrics`.

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

Each trap emulates just enough protocol to complete the handshake, grab the
interesting data, and return a plausible error. No interactive sessions,
no filesystem emulation — minimal attack surface on the honeypot itself.

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
| `adb` | `:5555` | ADB CNXN system identity — AUTH token challenge |
| `minecraft` | `:25565` | Handshake metadata + player names from login attempts |

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
| `RAN_<PROTO>_ADDR` | *(see traps table)* | Override listen address (comma-separated for multi-port) |

Multi-port: any trap can listen on multiple ports by passing a comma-separated
list. The protocol behavior is identical on each port; logs record the actual
`dest_port` per connection.

```bash
RAN_HTTP_ADDR=:8081,:8080,:8443,:3128   # HTTP on 4 ports
RAN_SSH_ADDR=:2222,:22                  # SSH on both default and standard port
RAN_SMTP_ADDR=:25,:587                  # SMTP on standard + submission port
```

Legacy variables `RAN_SSH=on`, `RAN_HTTP=on`, etc. still work but `RAN_TRAPS`
takes precedence when set.

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
| `RAN_CROWDSEC_MACHINE_ID` | | Machine ID for LAPI login (required when enabled) |
| `RAN_CROWDSEC_PASSWORD` | | Machine password for LAPI login (required when enabled) |
| `RAN_CROWDSEC_BAN_DURATION` | `4h` | Ban duration (`0` = permanent) |

Register the machine before starting rán:

```bash
cscli machines add -m ran-honeypot -p <password>
```

rán authenticates via machine-login (`POST /v1/watchers/login`) and
automatically refreshes the JWT token in the background. Scenario names
follow the pattern `custom/ran-<protocol>-trap`. Each alert includes a
self-contained ban decision — CrowdSec forwards it directly to bouncers
without needing a local scenario.

#### Ban Escalation

By default every attacker gets the same ban duration (`RAN_CROWDSEC_BAN_DURATION`,
default `4h`). CrowdSec Profiles can override this with dynamic escalation
based on how many times an IP has been banned before — no changes to rán
required.

> **Prerequisite:** `duration_expr` requires CrowdSec ≥ 1.4.

Add the following to your CrowdSec `profiles.yaml`. **Order matters** —
CrowdSec evaluates profiles top-to-bottom and stops at the first
`on_success: break`. Place the permanent-ban profile before the escalation
profile.

```yaml
# Permanent ban for persistent offenders (≥ 5 prior bans)
name: ran_permanent
filter: "Alert.Scenario startsWith 'custom/ran-' && GetDecisionsCount(Alert.GetValue()) >= 5"
decisions:
  - type: ban
    scope: Ip
    duration: 8760h
on_success: break
---
# Exponential escalation: 4h → 12h → 36h → 108h → 324h
name: ran_escalation
filter: "Alert.Scenario startsWith 'custom/ran-'"
decisions:
  - type: ban
    scope: Ip
duration_expr: "Sprintf('%dh', 4 * (3 ^ GetDecisionsCount(Alert.GetValue())))"
on_success: break
```

| Hit | Prior decisions | Duration |
|-----|-----------------|----------|
| 1st | 0 | 4h |
| 2nd | 1 | 12h |
| 3rd | 2 | 36h (1.5 days) |
| 4th | 3 | 108h (4.5 days) |
| 5th | 4 | 324h (13.5 days) |
| 6th+ | ≥ 5 | 8760h (permanent) |

Without these profiles, rán's embedded default decision applies unchanged —
existing deployments are not affected.

Verify escalation is working:

```bash
cscli decisions list -o json
```

> **Note:** `GetDecisionsCount()` queries CrowdSec's decision database.
> Expired decisions are purged based on `db_config.flush.max_age` — if the
> retention window is shorter than your escalation window, counters reset
> early. Check your retention settings with `cscli config show`.

## Log format

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

**`at least one trap must be enabled`** — set `RAN_TRAPS` or at least one
`RAN_<PROTO>=on` variable.

**Port already in use** — another service is on the default port. Override
with `RAN_<PROTO>_ADDR=:<port>`.

**CrowdSec alerts not arriving** — verify `RAN_CROWDSEC_URL` is reachable
from the container and the machine is registered (`cscli machines list`).

**UDP traps not receiving packets** — Docker needs explicit UDP port mapping:
`-p 53:53/udp`, not just `-p 53:53`.

**High connection volume causing drops** — increase `RAN_MAX_SESSIONS` and
`RAN_MAX_PER_IP`, or enable only the traps you need.

## Development

```bash
go test ./...                                    # tests
go vet ./... && golangci-lint run                 # lint
docker run --rm -i hadolint/hadolint < Dockerfile # Dockerfile lint
docker build -t ran:dev .                         # build
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Releases and the GHCR image are cut automatically by release-please.

## Image

Registry: `ghcr.io/st0o0/ran`
Tags: `latest`, `MAJOR.MINOR`, and exact `MAJOR.MINOR.PATCH` per release.
Architectures: `linux/amd64`, `linux/arm64`.

## License

MIT — see [`LICENSE.md`](LICENSE.md).
