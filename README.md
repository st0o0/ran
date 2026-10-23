# rán

[![Release](https://img.shields.io/github/v/release/st0o0/ran?sort=semver)](https://github.com/st0o0/ran/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-st0o0%2Fran-2496ED?logo=docker&logoColor=white)](https://github.com/st0o0/ran/pkgs/container/ran)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

Single-binary honeypot written in Go. Emulates 29 network services (SSH, RDP,
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

There are already good honeypots out there. The reason I built rán:

- **T-Pot** is excellent if you have a dedicated server, but it's 31 Docker
  containers, an ELK stack, and 8+ GB RAM. Too heavy for running alongside
  production services.
- **qeeqbox/honeypots** has broad protocol coverage in Python, but it needs a
  Python runtime and pip, and doesn't integrate with CrowdSec.

rán does one thing: catch probes, log them, report the source to CrowdSec. Single static Go
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
  (per-IP + global)       (access denied)            (class, no decision)
                                                           │
                                                           ▼
                                                    CrowdSec profile decides,
                                                  bouncers enforce (Caddy, nginx)
```

Each trap emulates just enough protocol to complete the handshake, grab the
interesting data, and return a plausible error. No interactive sessions,
no filesystem emulation. This keeps the attack surface of the honeypot minimal.

## Traps

### Remote access

| Name | Port | Captures |
|---|---|---|
| `ssh` | `:2222` | Credentials (OpenSSH banner, password auth) |
| `rdp` | `:3389` | Username (X.224 cookie extraction) |
| `vnc` | `:5900` | Auth challenge/response (VNC Authentication) |
| `telnet` | `:23` | Credentials (login/password prompts) |

### Web & proxy

| Name | Port | Captures |
|---|---|---|
| `http` | `:8081` | Credentials (WordPress + admin login pages) |
| `httpproxy` | `:8080` | Proxy targets + Proxy-Authorization credentials |
| `elasticsearch` | `:9200` | API requests (fake cluster responses). A plain `GET` without a body (`/`, `/_cluster/health`, other fingerprinting GETs) is a probe; any other method, or any request with a body, counts as a command |

### Databases

| Name | Port | Captures |
|---|---|---|
| `mysql` | `:3307` | Credentials (wire protocol, cleartext password) |
| `postgres` | `:5432` | Credentials (cleartext password auth) |
| `mssql` | `:1433` | Credentials (TDS Login7 with password decode) |
| `oracle` | `:1521` | Credentials (TNS connect descriptor) |
| `redis` | `:6379` | AUTH credentials + RESP command logging |
| `memcached` | `:11211` | Command logging (text protocol) |

### Mail

| Name | Port | Captures |
|---|---|---|
| `smtp` | `:25` | Credentials (AUTH LOGIN / PLAIN) |
| `pop3` | `:110` | Credentials (USER / PASS) |
| `imap` | `:143` | Credentials (LOGIN command) |

### Directory & network

| Name | Port | Captures |
|---|---|---|
| `ldap` | `:389` | Credentials (simple bind DN + password) |
| `smb` | `:445` | Credentials (NTLMSSP domain\user + workstation) |
| `socks5` | `:1080` | Credentials + proxy target addresses |
| `irc` | `:6667` | PASS credentials + NICK/USER/JOIN commands |

### IoT & industrial

| Name | Port | Captures |
|---|---|---|
| `mqtt` | `:1883` | Credentials (CONNECT client ID + user/pass) |
| `modbus` | `:502` | ICS payloads (function codes + registers) |
| `adb` | `:5555` | ADB CNXN system identity (AUTH token challenge) |
| `minecraft` | `:25565` | Handshake metadata + player names from login attempts. A server-list ping (status request) is a probe; only a login with a player name counts as payload |

### UDP

| Name | Port | Captures |
|---|---|---|
| `dns` | `:53` | Query domains + types (responds REFUSED) |
| `snmp` | `:161` | Community strings (v1/v2c GetRequest) |
| `sip` | `:5060` | SIP URIs + digest credentials |
| `ntp` | `:123` | Request metadata (drops monlist amplification) |

UDP source addresses are spoofable, so UDP traps log and count metrics only.
They never raise CrowdSec alerts (the UDP constructors take no alerter at all).
Inbound packets are rate limited per source and globally (see [Limits](#limits)).

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

Listen addresses are validated at startup (`host:port` or `:port`, port 1 to 65535).
Check a configuration without starting the traps: `ran check-config` prints the
problem and how to fix it, and exits 0 (valid) or 1 (invalid). The container
health check (`ran healthcheck`) also exits 1 when the configuration is invalid.

### Authentication behavior and PROXY protocol

| Variable | Default | Purpose |
|---|---|---|
| `RAN_MAX_AUTH_RETRIES` | `3` | Credential attempts per session before the trap disconnects (`0` = unlimited until the session timeout) |
| `RAN_AUTH_DELAY` | `0s` | Delay before answering a failed login; grows up to 4x per attempt |
| `RAN_SSH_TARPIT` | `off` | Hold SSH clients in an endless banner instead of the key exchange |
| `RAN_SSH_TARPIT_DURATION` | `30s` | Maximum tarpit time per SSH connection |
| `RAN_SSH_HOST_KEY_PATH` | `/data/ssh_host_key` | SSH host key file; generated on first start, so the directory must be writable (the image declares `/data` as a volume) |
| `RAN_PROXY_PROTOCOL` | `off` | Require a PROXY v1/v2 header on every TCP connection (see [Threat model](#threat-model)) |
| `RAN_<PROTO>_MAX_AUTH_RETRIES` | | Per-trap override of `RAN_MAX_AUTH_RETRIES` |
| `RAN_<PROTO>_AUTH_DELAY` | | Per-trap override of `RAN_AUTH_DELAY` |
| `RAN_<PROTO>_SESSION_TIMEOUT` | | Per-trap override of `RAN_SESSION_TIMEOUT` |

`<PROTO>` is the upper-case trap name, for example `RAN_SSH_SESSION_TIMEOUT`.

### Logging

| Variable | Default | Purpose |
|---|---|---|
| `RAN_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `RAN_LOG_FORMAT` | `json` | Log format: json, text |
| `RAN_LOG_PASSWORDS` | `off` | Password field in credential logs: `off` (omitted), `mask` (`*** (<length>)`), `on` (cleartext) |

Passwords are never sent to CrowdSec, regardless of `RAN_LOG_PASSWORDS`.

### Limits

| Variable | Default | Purpose |
|---|---|---|
| `RAN_SESSION_TIMEOUT` | `30s` | Max session duration (Go duration) |
| `RAN_MAX_SESSIONS` | `500` | Global concurrent session limit |
| `RAN_MAX_PER_IP` | `10` | Per-IP concurrent session limit |
| `RAN_UDP_RATE_PER_SOURCE` | `20` | UDP packets per second allowed per source address |
| `RAN_UDP_RATE_BURST` | `40` | UDP per-source burst size (must be at least `RAN_UDP_RATE_PER_SOURCE`, otherwise startup fails) |
| `RAN_UDP_RATE_GLOBAL` | `2000` | UDP packets per second allowed across all sources |

Excess UDP packets are dropped before a session is created (logged at debug only,
counted in `ran_udp_rate_limited_total`).
The limiter is per UDP trap, so "global" means per protocol: each of `dns`,
`ntp`, `snmp` and `sip` has its own global bucket. Per-source state is capped
at 100000 sources; once the cap is reached, packets from untracked sources are
only subject to the global bucket.
Request bodies are capped at 16 KiB (HTTP) and RESP, LDAP and line-based
protocols enforce fixed input limits.

On SIGTERM or SIGINT the listeners close and live sessions are closed at once
(they are not drained). Shutdown shares one 9 second deadline, below Docker's
default 10 second stop grace period regardless of `RAN_SESSION_TIMEOUT`: traps
and the metrics server get 4 seconds, then the CrowdSec sink drains its queue
within the remaining time (at most 5 seconds, with one last attempt if the
LAPI was failing). If every trap exits on its own while nothing asked to stop,
`ran` logs an error and exits with code 1 so the runtime restarts it.

### Metrics

| Variable | Default | Purpose |
|---|---|---|
| `RAN_METRICS_ADDR` | `:9550` | Prometheus metrics listen address |

Exposed metrics:

- `ran_connections_total{protocol,outcome}`: connection counter
- `ran_credentials_captured_total{protocol}`: credential capture counter
- `ran_active_sessions{protocol}`: active session gauge
- `ran_session_duration_seconds{protocol}`: session duration histogram (buckets 0.1 s to 120 s)
- `ran_crowdsec_alerts_dropped_total{protocol}`: alerts dropped because the delivery queue was full
- `ran_panics_recovered_total{protocol}`: panics recovered at connection and packet boundaries
- `ran_proxy_protocol_dropped_total{protocol}`: connections closed by the PROXY protocol listener (no valid header, deadline, handshake limit, stalled consumer)
- `ran_udp_rate_limited_total{protocol}`: UDP packets dropped by the packet rate limiter
- `ran_sessions_rejected_total{protocol}`: TCP connections rejected by the session limiter (`RAN_MAX_SESSIONS`, `RAN_MAX_PER_IP`)
- `ran_probe_summary_suppressed_sessions_total`: probe sessions whose per-session log lines were replaced by a summary
- `ran_tracked_entries{map}`: entries in the bounded tracking maps (`map`: `scan`, `probe`, `cooldown`)
- `ran_tracked_evictions_total{map}`: live entries evicted because a map was full; a rising rate means `RAN_CROWDSEC_MAX_TRACKED` is too small
- `ran_crowdsec_push_duration_seconds`: histogram of CrowdSec LAPI push request durations
- `ran_crowdsec_push_errors_total`: failed LAPI pushes (transport errors and non-2xx answers)
- `ran_crowdsec_queue_length`: alerts waiting in the send queue
- `ran_crowdsec_pipeline_total{protocol,stage}`: CrowdSec alert pipeline events. Stages: `received`, `invalid` (rejected source address), `closed` (raised after shutdown), `filtered` (class not in `RAN_BAN_ON`), `cooldown` (within `RAN_ALERT_COOLDOWN`), `queued`, `dropped`, `sent`, `failed`, `released` (cooldown slot freed after a failed push, so the source is reported again). The 0.3.x stages `cached` and `deduplicated` no longer exist. Per-class counts are not a label (cardinality); the class is in the alert meta and the logs.

### CrowdSec

rán is a sensor: it classifies every TCP session, aggregates the noise and
pushes alerts to the CrowdSec LAPI. **rán does not ban anything by itself.**
Alerts carry no decisions; a CrowdSec profile decides whether and for how long
an IP is banned (see [Escalation with CrowdSec profiles](#escalation-with-crowdsec-profiles)).
Without a profile nothing is banned.

| Variable | Default | Purpose |
|---|---|---|
| `RAN_CROWDSEC` | `off` | Enable CrowdSec LAPI alerting |
| `RAN_CROWDSEC_URL` | | CrowdSec LAPI URL (required when enabled) |
| `RAN_CROWDSEC_MACHINE_ID` | | Machine ID for LAPI login (required when enabled) |
| `RAN_CROWDSEC_PASSWORD` | | Machine password for LAPI login (required when enabled) |
| `RAN_BAN_ON` | `attack,scan` | Classes that produce a CrowdSec alert (subset of `probe,attack,scan`). `probe` stays in logs and metrics only unless listed |
| `RAN_ALERT_COOLDOWN` | `4h` | At most one alert per IP and class per cooldown (`0s` = disabled) |
| `RAN_PROBE_SUMMARY_WINDOW` | `60s` | Window of the aggregated probe summary log line (`0s` = one log line per probe session) |
| `RAN_CROWDSEC_BATCH_INTERVAL` | `10s` | Batch flush interval (`0s` = immediate, no batching) |
| `RAN_CROWDSEC_BATCH_SIZE` | `50` | Max alerts per batch POST |
| `RAN_CROWDSEC_MAX_TRACKED` | `20000` | Max entries in each in-memory map: alert cooldown, scan tracker and probe summaries (see sizing below) |

`RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and
`RAN_CROWDSEC_DEDUP_WINDOW` were removed in 0.4.0. They are ignored; rán logs a
one-time warning at startup if one is still set.

**Memory sizing.** Each tracked entry costs about 400 bytes per structure, and the
cooldown, the scan tracker and the probe log share `RAN_CROWDSEC_MAX_TRACKED`, so
20000 entries are roughly 25 MB at the cap (a 1M unique-source flood peaked at
227 MB heap with a cap of 100000). Size the container memory limit for the cap you
choose, and set `GOMEMLIMIT` to about 80 percent of the container limit (for example
`GOMEMLIMIT=100MiB` for a 128 MB limit) so the garbage collector works harder before
the kernel OOM-kills the process.

#### Classification

| Class | Meaning |
|---|---|
| `probe` | Connect and banner only: no auth attempt, command or payload byte |
| `attack` | At least one auth attempt, command or payload byte |
| `scan` | The same source IP touched at least 3 distinct TCP trap protocols within about 10 minutes |

Scan detection never counts UDP (spoofable) or non-public source addresses, and
its in-memory map is capped (oldest entries are evicted first, which only delays
a scan classification). A scan is always its own alert, even if the session that
crossed the threshold was only a probe; its scenario uses the protocol that
crossed it. `scan` outranks `attack`, which outranks `probe`.

The class is sent as event meta (`class`), together with `protocol`,
`dest_port`, `auth_attempts`, `commands` and `payload_bytes`. Scenario names stay
`custom/ran-<protocol>-trap` for every class, and `source.ip` and `source.value`
are both set, so geo enrichment keeps working.

Sessions are classified from the counters when they end, so a trap that logs a
command, payload or auth attempt ends as `attack` even if it did not alert
mid-session (redis, memcached, imap and irc alert on the first command with only
the command name as meta). Pure fingerprinting stays a `probe`: Elasticsearch
plain GET requests without a body and Minecraft server-list pings. Per-trap
tuning for single-request protocols (a modbus request, an ADB CONNECT) is a
planned follow-up.

#### Logging of probes

Probe sessions are not logged one by one. Per source IP and
`RAN_PROBE_SUMMARY_WINDOW` rán writes one summary line
(`action: probe_summary`, `sessions`, `protocols`). Attack and scan sessions keep
their full per-event lines (credentials, commands, payloads). The `ran_*`
metrics are still updated per session, so dashboards are unaffected.

#### Alert pipeline

```
trap session ──▶ Classify (probe / attack / scan) ──▶ Alert pipeline ──▶ POST /v1/alerts
                                                       │
   IP validation ─▶ class filter (RAN_BAN_ON) ─▶ cooldown ─▶ batch queue
        invalid          filtered                  cooldown       queued / dropped
```

1. **IP validation**: only publicly routable addresses pass (stage `invalid` otherwise).
2. **Class filter**: classes not in `RAN_BAN_ON` stop here (stage `filtered`).
3. **Cooldown**: at most one alert per IP and class per `RAN_ALERT_COOLDOWN`
   (stage `cooldown`). A move to a higher class (probe to attack, attack to scan)
   passes once; a lower class is suppressed while a higher one is cooling down.
   The slot is only consumed when the alert is queued; if the queue is full the
   alert is dropped and may be retried. With the default 4h cooldown a continuous
   attacker produces about one alert per ban period, so CrowdSec's
   `GetDecisionsCount` counts episodes, not packets.
4. **Batch queue**: alerts are flushed as one POST on a timer or at the batch size.

When a map is full, the oldest entries are evicted. An evicted cooldown entry can
alert again, so a full map means more LAPI traffic.

Only the TCP peer address is used as alert identity. The HTTP trap logs
`X-Real-IP` / `X-Forwarded-For` as `claimed_client_ip` but never alerts on it
(behind a trusted proxy, use `RAN_PROXY_PROTOCOL`). Alerts are accepted only
for publicly routable addresses. Private (RFC 1918, ULA), CGNAT (100.64.0.0/10),
loopback, link-local, unspecified, multicast, reserved, documentation, benchmark,
6to4, NAT64 (including 64:ff9b:1::/48), IETF protocol assignment (2001::/23), 3fff::/20, 5f00::/16 and IPv4-compatible sources are dropped (pipeline stage `invalid`), so
LAN-only deployments produce no CrowdSec alerts.

With `RAN_PROXY_PROTOCOL`, the PROXY v1 or v2 header is required. A connection
must send a valid header within 3 seconds; a connection that sends other bytes,
closes early or stays silent is closed and counted in
`ran_proxy_protocol_dropped_total`, never handled as a plain connection. A
silent peer does not block other clients. At most 1024 connections may be
waiting for a header (or for the trap to take them) at once; further ones are
closed immediately and counted too. Only enable this mode when ran is reachable
solely from a trusted proxy or tunnel: any peer that can connect directly can
forge a header and choose its own source address. A source allowlist for
trusted proxies is a possible future change.

Register the machine before starting rán:

```bash
cscli machines add -m ran-honeypot -p <password>
```

rán authenticates via machine-login (`POST /v1/watchers/login`) and
automatically refreshes the JWT token in the background. Alerts are pushed with
`remediation: true`, an empty `decisions` list, `simulated: false`, and
`source.scope: Ip`. Decisions created by your profiles have the origin
`crowdsec`, not `ran`.

Example docker-compose:

```yaml
services:
  ran:
    image: ghcr.io/st0o0/ran:latest
    environment:
      RAN_TRAPS: ssh,http,ftp,smtp,vnc,rdp
      RAN_CROWDSEC: "on"
      RAN_CROWDSEC_URL: http://crowdsec:8080
      RAN_CROWDSEC_MACHINE_ID: ran-honeypot
      RAN_CROWDSEC_PASSWORD: ${CROWDSEC_PASSWORD}
      RAN_BAN_ON: attack,scan
      RAN_ALERT_COOLDOWN: 4h
```

#### Escalation with CrowdSec profiles

CrowdSec evaluates `profiles.yaml` only for alerts that carry no decisions,
which is exactly what rán sends. Select on the class with the **event** form
`Alert.Events[0].GetMeta("class")`: `Alert.GetMeta("class")` reads only
alert-level meta and matches nothing. Profiles run top to bottom and stop at the
first `on_success: break`, so put the `scan` profile first.

```yaml
# scan: one IP probing many protocols
name: ran_scan
filters:
  - Alert.GetScenario() startsWith "custom/ran-" && Alert.Events[0].GetMeta("class") == "scan"
decisions:
  - type: ban
    scope: Ip
    duration: 1h
duration_expr: "Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))"
on_success: break
---
# attack: credentials, commands or payloads
name: ran_attack
filters:
  - Alert.GetScenario() startsWith "custom/ran-" && Alert.Events[0].GetMeta("class") == "attack"
decisions:
  - type: ban
    scope: Ip
    duration: 1h
duration_expr: "Sprintf('%.0fh', min(168.0, 3 ^ GetDecisionsCount(Alert.GetValue())))"
on_success: break
# probe: no profile, so a probe alert (only sent with RAN_BAN_ON=probe,...) never bans
```

`duration_expr` overrides the profile `duration` (the fallback), and the newest
decision replaces the older one. The `scan` class uses the same formula as
`attack` in this example. If you want scanners to stay out longer, give
the `scan` profile a harder formula, for example a larger base or a longer cap.

| Alert for the IP | Prior decisions | Ban |
|---|---|---|
| 1st | 0 | 1h |
| 2nd | 1 | 3h |
| 3rd | 2 | 9h |
| 4th | 3 | 27h |
| 5th | 4 | 81h |
| 6th and later | 5 or more | 168h (cap) |

Two expression pitfalls, both verified against CrowdSec v1.8.1:

- Use lowercase `min`. The capitalized `Min` does not compile and CrowdSec
  exits fatally with `unknown name Min`.
- Use `%.0fh`, not `%dh`. `3 ^ n` is a float, so `%dh` silently falls back to
  the base `duration` (`%!d(float64=...)`).

> **Prerequisite:** `duration_expr` requires CrowdSec 1.4 or later.

The profile syntax above is verified against CrowdSec v1.8.1 (profile syntax,
expression and decisions tested). Use the list key `filters:`; the singular
`filter:` key is rejected and the LAPI exits with `field filter not found in
type csconfig.ProfileCfg`.

Verify with:

```bash
cscli alerts list
cscli decisions list -o json
```

#### CrowdSec behaviors to know

- **No profile, no ban.** rán logs a startup line stating that it does not ban by itself.
- **Escalation memory is the alert history.** `GetDecisionsCount` counts the
  alerts CrowdSec still stores for the IP. `db_config.flush.max_items` deletes
  alerts without an active decision, and `max_age` ages them out; a deleted
  alert drops out of the count, which lowers or resets the escalation level
  (observed: 27h instead of 81h, and a restart at 1h). Active bans are never
  expired early. Size `max_items` and `max_age` so the history covers the
  longest escalation step (168h) at your alert rate. Before the cooldown design
  rán created about 4000 alerts per day on a busy host; the per-episode
  cooldown lowers that, but check your own rate with `cscli alerts list`.
- **CAPI sharing.** Alerts without decisions are still forwarded to the Central
  API (custom scenarios) unless they are `simulated: true`. rán always sends
  `simulated: false`; if you do not want to share, disable CAPI sharing on the
  CrowdSec side. Simulated alerts are not usable for bans: they create
  simulated decisions that are not in the bouncer stream. rán has no option to
  send simulated alerts.
- **Allowlists apply.** An alert without decisions for an allowlisted IP is
  dropped by CrowdSec and not stored.
- **Machine credentials stay required** (`cscli machines add`).

#### Migrating from 0.3.x

1. Add the example `profiles.yaml` (or an equivalent) to CrowdSec and reload it.
   Without a profile, 0.4.0 bans nothing.
2. Remove `RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and
   `RAN_CROWDSEC_DEDUP_WINDOW`; optionally set `RAN_BAN_ON`, `RAN_ALERT_COOLDOWN`
   and `RAN_PROBE_SUMMARY_WINDOW`.
3. Update Grafana panels and alerts that use `stage="cached"` or
   `stage="deduplicated"` of `ran_crowdsec_pipeline_total`: use `cooldown` and
   `filtered` instead.
4. Expect fewer log lines: probe sessions are now summarized (see above).
5. Decisions with origin `ran` from 0.3.x expire normally;
   `GetDecisionsCount` stays inflated for old IPs because every re-push added a row.

Upgrading from 0.3.7: UDP traps (`dns`, `ntp`, `snmp`, `sip`) no longer raise
alerts, so the `custom/ran-{dns,ntp,snmp,sip}-trap` scenarios stop appearing.
The HTTP log field `client_ip` is now `claimed_client_ip`. The `password` log
field is omitted unless `RAN_LOG_PASSWORDS` is `mask` or `on`.

Upgrading to 0.4.0 (breaking): the image now runs as user `65532`. An existing
`/data` volume created by an older release is owned by root, so `ran` cannot
read or write the SSH host key there. Fix it once with
`chown -R 65532:65532` on the volume (for example
`docker run --rm -v ran-data:/data busybox chown -R 65532:65532 /data`).
Until then `ran` logs a warning and uses a new host key on every restart.
Also user-visible: the MySQL banner now reports version `8.0.36`, and the SMTP
trap identifies itself as `mx.localdomain`, so fingerprints of the old
banners change.

## Threat model

rán is a sensor, not a defense. It exposes deliberately weak fake services and
reports who touched them; it does not protect the host it runs on.

- **Spoofing resistance.** The alert identity is always the TCP peer address.
  Header values (`X-Forwarded-For`, `X-Real-IP`) are only logged as
  `claimed_client_ip`. UDP source addresses can be forged, so UDP traps never
  raise alerts; they only log and count metrics. Only TCP sessions with a
  publicly routable peer can produce a CrowdSec alert.
- **PROXY protocol trust.** With `RAN_PROXY_PROTOCOL=on` the address in the
  header is trusted as the peer. Any host that can reach the port directly can
  forge it, so enable it only when rán is reachable solely from your proxy or
  tunnel (firewall the listener accordingly).
- **Detectability.** Banners are generic and plausible, but a determined
  attacker can fingerprint any honeypot. Do not rely on rán staying hidden.
- **Isolation.** Run it unprivileged, without capabilities and with a read-only
  filesystem (see below). Never place it on a network segment with sensitive
  hosts.

### Recommended container settings

The image runs as user `65532` and needs write access only to `/data` (the SSH
host key). Docker sets `net.ipv4.ip_unprivileged_port_start=0` inside containers, so
low ports work without `NET_BIND_SERVICE`. Other runtimes may need that sysctl
or higher ports (map them from the host, for example `"22:2222"`).

```yaml
services:
  ran:
    image: ghcr.io/st0o0/ran:latest
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    user: "65532:65532"
    mem_limit: 128m
    environment:
      GOMEMLIMIT: 100MiB          # about 80 percent of mem_limit
    volumes:
      - ran-data:/data            # SSH host key
    tmpfs:
      - /tmp
volumes:
  ran-data:
```

Sizing: memory is dominated by the tracking maps (see *Memory sizing* above) and
by concurrent sessions (`RAN_MAX_SESSIONS`). Set `GOMEMLIMIT` to about 80
percent of the container limit.

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

Actions: `connect`, `auth_attempt`, `command`, `payload`, `disconnect`, `probe_summary`.
Connect and disconnect lines are written for sessions that do something; probe
sessions are summarized (see [Logging of probes](#logging-of-probes)).

## Troubleshooting

**`at least one trap must be enabled`**: set `RAN_TRAPS` to a comma-separated
list of traps. `ran check-config` validates the whole configuration.

**Port already in use**: another service is on the default port. Override
with `RAN_<PROTO>_ADDR=:<port>`.

**CrowdSec alerts not arriving**: verify `RAN_CROWDSEC_URL` is reachable
from the container and the machine is registered (`cscli machines list`).

**Alerts arrive but nothing is banned**: rán does not create decisions. Add a
CrowdSec profile for the `attack` and `scan` classes (see
[Escalation with CrowdSec profiles](#escalation-with-crowdsec-profiles)).

**UDP traps not receiving packets**: Docker needs explicit UDP port mapping:
`-p 53:53/udp`, not just `-p 53:53`.

**High connection volume causing drops**: increase `RAN_MAX_SESSIONS` and
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

MIT, see [`LICENSE.md`](LICENSE.md).
