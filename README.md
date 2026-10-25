# rán

[![Release](https://img.shields.io/github/v/release/st0o0/ran?sort=semver)](https://github.com/st0o0/ran/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-st0o0%2Fran-2496ED?logo=docker&logoColor=white)](https://github.com/st0o0/ran/pkgs/container/ran)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

Single-binary honeypot written in Go. Emulates 40 network services (SSH, RDP,
Modbus, MQTT, …), captures credentials and payloads as structured JSON, and
pushes classified alerts to CrowdSec, whose profiles decide the bans. No external
dependencies, ~8 MB scratch image.

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

There are good honeypots out there, and they answer different questions. rán is
built for one job: be a cheap, hardened **sensor** whose alerts a CrowdSec
profile can act on.

- **Alert quality.** Every TCP session is classified as `probe`, `attack` or
  `scan`, repeated alerts per source are limited by a cooldown, and alerts carry
  no decisions, so CrowdSec profiles can escalate bans per class and per repeat
  offender.
- **Hardened by design.** The alert identity is always the socket peer, UDP traps
  never alert (spoofable), every read is bounded, passwords never leave the host,
  and the parsers are fuzzed.
- **Small and easy to run.** One static binary, environment-variable config,
  `check-config`, a health endpoint and Prometheus metrics.

What rán deliberately does not do: there is no interactive session (no shell, no
filesystem emulation, no file capture, no LLM), most traps are stubs that handle
one handshake, and it is not stealthy. To study what attackers do after they log
in, use Cowrie, Beelzebub or T-Pot. See the
[comparison](https://st0o0.github.io/ran/comparison) for a side by side table of Cowrie, OpenCanary,
qeeqbox/honeypots, T-Pot and Beelzebub (facts last checked October 2026).

## Quick start

Pick your traps, start the container:

```bash
docker run --rm --name ran  -e RAN_TRAPS=ssh,http,ftp  -p 2222:2222 -p 8081:8081 -p 21:21 -p 9550:9550  ghcr.io/st0o0/ran:latest
```

Watch the logs with `docker logs -f ran`. Prometheus metrics are at `:9550/metrics`.
The [config builder](https://st0o0.github.io/ran/builder) turns a deployment scenario into an env file, a
compose file or a `docker run` line, and `ran check-config` validates an
environment without starting the traps. rán does not ban anything by itself: add
the CrowdSec profile printed by `ran crowdsec-profile` (see
[CrowdSec](https://st0o0.github.io/ran/crowdsec)).

## How it works

```
attacker connects ──▶ protocol handshake ──▶ credential / command / payload capture
        │                       │                            │
        │                       │                            ▼
        │                       │                    structured JSON → stdout
        │                       │                            │
        ▼                       ▼                            ▼
   rate limiter           plausible error            CrowdSec LAPI alert
  (per-IP + global)       (access denied)            (class, no decision)
                                                           │
                                                           ▼
                                                    CrowdSec profile decides,
                                                  bouncers enforce (Caddy, nginx)
```

Each trap emulates just enough protocol to complete the handshake, grab the
interesting data, and return a plausible error. What is captured depends on the
protocol: credentials for the login protocols, commands for line protocols such
as Redis or IMAP, and payload metadata for binary protocols. There is no
post-login session (no shell for `ssh` or `telnet`) and no filesystem emulation,
which keeps the attack surface of the honeypot minimal.

## Traps

40 traps; ports, transports and what each one captures are listed on the
[traps page](https://st0o0.github.io/ran/traps), which is generated from the code.

| Group | Traps |
|---|---|
| Remote access | `ssh`, `rdp`, `vnc`, `telnet`, `ftp` |
| Web & proxy | `http`, `https`, `httpproxy`, `elasticsearch` |
| Containers & orchestration | `docker`, `kubernetes`, `mcp` |
| Databases | `mysql`, `postgres`, `mssql`, `oracle`, `redis`, `memcached`, `mongodb` |
| Mail | `smtp`, `pop3`, `imap` |
| Directory & network | `ldap`, `smb`, `socks5`, `irc` |
| IoT & industrial | `s7comm`, `enip`, `mqtt`, `modbus`, `adb`, `minecraft` |
| Printers | `pjl`, `ipp` |
| Catch-all & banner (no default port) | `catchall`, `banner` |
| UDP (log and metrics only, never alert) | `dns`, `snmp`, `sip`, `ntp` |

## Threat model

rán is a sensor, not a defense. It exposes deliberately weak fake services and
reports who touched them; it does not protect the host it runs on.

- **Spoofing resistance.** The alert identity is always the TCP peer address.
  Header values (`X-Forwarded-For`, `X-Real-IP`) are only logged as
  `claimed_client_ip`. UDP source addresses can be forged, so UDP traps never
  raise alerts. Only TCP sessions with a publicly routable peer can produce a
  CrowdSec alert.
- **PROXY protocol trust.** Only peers listed in `RAN_PROXY_TRUSTED` (mandatory
  with `RAN_PROXY_PROTOCOL`) may send a PROXY header; `any` removes that
  protection, so list your proxies and firewall the listener.
- **Detectability.** Banners are generic and can be seeded per instance, but a
  determined attacker can fingerprint any honeypot. Do not rely on rán staying
  hidden.
- **Isolation.** Run it unprivileged, without capabilities and with a read-only
  filesystem, and never on a network segment with sensitive hosts. The
  [hardening page](https://st0o0.github.io/ran/hardening) has the full threat model and a hardened compose
  example.

## Documentation

Full reference at **https://st0o0.github.io/ran/**:

- [Getting started](https://st0o0.github.io/ran/getting-started) and the [config builder](https://st0o0.github.io/ran/builder)
- [Traps](https://st0o0.github.io/ran/traps)
- [Configuration](https://st0o0.github.io/ran/configuration): trap selection, authentication behavior, HTTP fixtures, banner profiles, logging, ignore list, limits
- [Classification and alerts](https://st0o0.github.io/ran/classification-and-alerts)
- [CrowdSec](https://st0o0.github.io/ran/crowdsec): connecting, profiles, escalation, upgrade notes
- [Metrics](https://st0o0.github.io/ran/metrics) and [log format](https://st0o0.github.io/ran/log-format)
- [Hardening](https://st0o0.github.io/ran/hardening): threat model, reverse proxy and PROXY protocol, container settings
- [Troubleshooting](https://st0o0.github.io/ran/troubleshooting)
- [Comparison with alternatives](https://st0o0.github.io/ran/comparison)

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

MIT, see [`LICENSE.md`](LICENSE.md).
