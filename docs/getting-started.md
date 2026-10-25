# Getting started

rán is a single-binary honeypot. It emulates 40 network services, captures
credentials and payloads as structured JSON, and can push classified alerts to
CrowdSec, whose profiles decide the bans. This page takes you from nothing to a
running sensor you have checked yourself. For the design and the threat model see
[Hardening](/hardening); for every setting see [Configuration](/configuration).

## Prerequisites

- A Linux host with Docker and the Compose plugin. The image is a static binary on
  `scratch` for `linux/amd64` and `linux/arm64`.
- Ports you can expose. Each trap listens on a default port; free the ones you
  want or move them with `RAN_<PROTO>_ADDR` (see below).
- Optional: a CrowdSec local API (LAPI) and a registered machine, only if you want
  bans. Without it rán still logs everything and serves metrics.

## 1. Build your configuration

Open the [config builder](/builder), pick a scenario, tick the traps and copy the
`docker-compose.yml`. It writes only values that differ from the default, adds the
hardening flags (read-only filesystem, no capabilities, non-root user), a `/data`
volume and publishes metrics on loopback only. Save the output as
`docker-compose.yml`.

## 2. Validate it

`check-config` validates an environment without starting any trap. Pass the same
variables you put in the compose file:

```bash
docker run --rm -e RAN_TRAPS=ssh,http,ftp ghcr.io/st0o0/ran check-config
```

It prints the problem and how to fix it and exits 0 (valid) or 1 (invalid).

## 3. Run it

```bash
docker compose up -d
docker compose logs -f ran
```

On startup rán logs a `listening` line for each trap. A trap whose port is taken
logs `trap failed to start` and is skipped while the others keep running.

Without compose, the equivalent single command is below. The `/data` volume keeps
the SSH host key and the banner seed across restarts; without it both change every
time the container is recreated.

```bash
docker run -d --name ran -v ran-data:/data \
  -e RAN_TRAPS=ssh,http,ftp \
  -p 2222:2222 -p 8081:8081 -p 21:21 -p 127.0.0.1:9550:9550 \
  ghcr.io/st0o0/ran:latest
```

## 4. Confirm it works

Touch a trap from another shell and watch the log:

```bash
nc localhost 2222            # prints an SSH banner; press Ctrl+C
curl -i http://localhost:8081/   # answers like a web server
docker logs ran | tail -n 5  # one JSON line per session
```

Check the health endpoint and the metrics (both unauthenticated):

```bash
curl http://127.0.0.1:9550/healthz
curl -s http://127.0.0.1:9550/metrics | grep ran_connections_total
```

`ran_connections_total` counts the connection you just made. See
[Log format](/log-format) and [Metrics](/metrics) for the fields.

## Ports and privileges

SSH defaults to `2222` and HTTP to `8081`, not `22` and `80`, so the container
works without extra privileges. Docker allows low ports inside containers, so you
can also set `RAN_SSH_ADDR=:22`. To keep the defaults inside the container and
expose a classic port on the host, map it: `"22:2222"`. Move your real SSH daemon
first, or the host port is already taken.

## Metrics are not public

`/metrics` and `/healthz` have no authentication. Publish them on loopback
(`127.0.0.1:9550:9550`) as the examples do. A scraper on the host reaches that
address; a scraper in another container does not, because container loopback and
host loopback differ. Put the scraper on the same Docker network and scrape
`ran:9550` instead, without publishing the port.

## Banning with CrowdSec

rán does not ban by itself. Pick the *With CrowdSec* scenario in the builder,
register a machine (`cscli machines add`), install the profile printed by
`ran crowdsec-profile` and follow [CrowdSec](/crowdsec). The LAPI must be reachable
at the hostname in `RAN_CROWDSEC_URL` (the builder uses `crowdsec`); the first
failed login is fatal, see [Troubleshooting](/troubleshooting).

## Image

Registry: `ghcr.io/st0o0/ran`
Tags: `latest`, `MAJOR.MINOR`, and exact `MAJOR.MINOR.PATCH` per release.
Architectures: `linux/amd64`, `linux/arm64`.

## Next steps

[Traps](/traps), [Configuration](/configuration), [Hardening](/hardening). To work
on rán itself, see `CONTRIBUTING.md` in the repository.
