# Getting started

Single-binary honeypot written in Go. Emulates 40 network services (SSH, RDP,
Modbus, MQTT, …), captures credentials and payloads as structured JSON, and
pushes classified alerts to CrowdSec, whose profiles decide the bans. No external
dependencies, ~8 MB scratch image.

Named after the Norse goddess who catches sailors in her net.

## Example compose file

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

## Quick start

Pick your traps, start the container:

```bash
docker run --rm --name ran \
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

## Image


Registry: `ghcr.io/st0o0/ran`
Tags: `latest`, `MAJOR.MINOR`, and exact `MAJOR.MINOR.PATCH` per release.
Architectures: `linux/amd64`, `linux/arm64`.

## Development

```bash
go test ./...                                    # tests
go vet ./... && golangci-lint run                 # lint
docker run --rm -i hadolint/hadolint < Dockerfile # Dockerfile lint
docker build -t ran:dev .                         # build
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
Releases and the GHCR image are cut automatically by release-please.
