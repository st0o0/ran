# rán

[![Release](https://img.shields.io/github/v/release/st0o0/ran?sort=semver)](https://github.com/st0o0/ran/releases)
[![GHCR](https://img.shields.io/badge/ghcr.io-st0o0%2Fran-2496ED?logo=docker&logoColor=white)](https://github.com/st0o0/ran/pkgs/container/ran)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

Single-binary honeypot written in Go. Emulates 30 network services (SSH, RDP,
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

| | Cowrie | OpenCanary | qeeqbox/honeypots | T-Pot | Beelzebub | rán |
|---|---|---|---|---|---|---|
| Language / runtime | Python 3.11+ | Python 3.10+ | Python (pip) | Docker Compose stack | Go | Go, static binary |
| Focus | Interactive SSH/Telnet shell | Tripwire for internal networks | Many protocol servers | Platform of many honeypots | Deception framework, optional LLM | Sensor for blocklists |
| Protocols | SSH, Telnet (SFTP/SCP) | multi-protocol, list not verified | 29 modules | 31 honeypots listed | SSH, HTTP, TCP, Telnet, MCP | 30 stubs |
| Post-login shell, file capture | yes | no | no | via Cowrie, Dionaea | optional LLM shell | no (by design) |
| CrowdSec | log parsing via the Hub | none found | none found | none found | none found | native LAPI alerts, classified |
| Footprint | Python process | Python process | Python process | 8 GB (sensor) to 16 GB (hive) RAM | Go binary | about 13 MB working set idle, all 29 traps |
| Prometheus metrics | no | no | no | via the stack | optional | built in |
| Licence | see repo | BSD-3 | AGPL-3.0 | GPL-3.0 | GPL-3.0 | MIT |

Read from the projects' own READMEs in October 2026; check them for current
details. "None found" means the README does not mention it. The memory figure
for rán was measured on Windows with all 29 traps enabled and no traffic.

What rán does better:

- **Alert quality.** Every TCP session is classified as `probe`, `attack` or
  `scan`, repeated alerts per source are limited by a cooldown, and alerts carry
  no decisions, so CrowdSec profiles can escalate bans per class and per repeat
  offender.
- **Hardened by design.** The alert identity is always the socket peer, UDP traps
  never alert (spoofable), every read is bounded, passwords never leave the host,
  and the parsers are fuzzed.
- **Small and easy to run.** One static binary, environment-variable config,
  `check-config`, a health endpoint and Prometheus metrics.

What rán deliberately does not do, and where to look instead:

- **No interactive session.** There is no shell, no filesystem emulation, no file
  download or upload capture and no LLM. To study what attackers type after they
  log in, use Cowrie, Beelzebub or T-Pot.
- **Stubs, not servers.** Most traps handle one handshake and return a plausible
  error. Depth varies by protocol (see [Traps](#traps)).
- **Not stealthy.** Banners are generic; a determined attacker can fingerprint any
  honeypot (see [Threat model](#threat-model)).

Use rán to turn internet-facing probes into CrowdSec bans on a small host. Choose
or add another honeypot when you want attacker behavior, malware samples or an
internal tripwire.

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

## Traps

### Remote access

| Name | Port | Captures |
|---|---|---|
| `ssh` | `:2222` | Credentials (OpenSSH banner, password auth only; public-key and keyboard-interactive attempts are rejected without being logged) |
| `rdp` | `:3389` | Username (X.224 cookie extraction); one attempt per session |
| `vnc` | `:5900` | Auth challenge/response (VNC Authentication); no password is recoverable from it without cracking the DES response |
| `telnet` | `:23` | Credentials (login/password prompts) |
| `ftp` | `:21` | Credentials (`USER` / `PASS`). Banner `220 FTP Server ready.`, lines up to 512 bytes. Every other command except `QUIT` gets `530` and is not logged |

### Web & proxy

| Name | Port | Captures |
|---|---|---|
| `http` | `:8081` | Every request is logged with method, path (no query string), `Host`, `User-Agent` and a header subset (values cut to 256 bytes, control characters replaced). Requests for known exploit and recon paths (`/.env`, `/.git/`, `/actuator`, `/cgi-bin/`, `/phpmyadmin`, traversal and so on) and requests carrying a JNDI lookup (`${jndi:`, also nested or percent encoded) in the request line or a header value are commands, so they classify as `attack`. Basic `Authorization` is captured as credentials, `POST` form logins (WordPress `/wp-login.php`, `/admin`, and a generic page for every other path) as before. A `POST`, `PUT` or `PATCH` body that is not a form login (JSON, XML) counts as payload bytes, read up to 16 KiB. Any other `GET`/`HEAD` stays a `probe`. Alert meta adds `path`, `method` and `user_agent`. Responses carry `Server: Apache/2.4.62` |
| `https` | `:8443` | The `http` trap behind TLS, with the same request handling and classification (exploit paths, JNDI, Basic auth and login forms are `attack`; a completed handshake without a request, a failed handshake and non-TLS bytes stay a `probe`). Uses two self-signed certificates (`CN=localhost`, ECDSA P-256 and RSA-2048), generated on first start and persisted at `RAN_HTTPS_CERT_PATH`. The ClientHello is fingerprinted before negotiation, so clients that fail the handshake are still logged (`tls client hello`): SNI, JA3 and JA4 (GREASE removed, lists capped, first TLS record only). Alert meta adds `sni`, `ja3` and `ja4` to the `http` meta. No client certificates. Accepts old clients: TLS 1.0 to 1.3 and every cipher suite Go implements, including RSA key exchange, 3DES, RC4 and CBC-SHA256 (see the threat notes) |
| `httpproxy` | `:8080` | `CONNECT host:port` and absolute-URI requests (`METHOD URL`, without userinfo, query and fragment) as commands, plus Basic `Proxy-Authorization` credentials. Requests with neither get `400` and stay a probe |
| `elasticsearch` | `:9200` | API requests with fake cluster responses. Classification: `GET`/`HEAD` without a body, and any `GET` to `/` or `/_cluster/health`, are probes. `POST`, `PUT`, `DELETE`, or `GET`/`HEAD` with a body on other paths are commands, recorded as `METHOD /path` only (no query string, no body; the body is read up to 4096 bytes). Other methods get `405` and are not recorded |

`http`, `https`, `httpproxy` and `elasticsearch` start a session per connection (`http`, `https`) or per request (`httpproxy`, `elasticsearch`).

### Databases

| Name | Port | Captures |
|---|---|---|
| `mysql` | `:3307` | Username and the client's auth response (greeting reports version `8.0.36` and offers `mysql_clear_password`; the value is plaintext only for clients that use the cleartext plugin, otherwise it is the client's scrambled response) |
| `postgres` | `:5432` | Credentials (cleartext password auth) |
| `mssql` | `:1433` | Credentials (TDS Login7 with password decode) |
| `oracle` | `:1521` | `USER` and `SERVICE_NAME` from the TNS CONNECT descriptor; no password |
| `redis` | `:6379` | `AUTH` credentials + RESP and inline command logging |
| `memcached` | `:11211` | Command logging (text protocol) |

### Mail

| Name | Port | Captures |
|---|---|---|
| `smtp` | `:25` | Credentials (AUTH LOGIN / PLAIN) |
| `pop3` | `:110` | Credentials (USER / PASS) |
| `imap` | `:143` | Credentials (LOGIN command); other commands except `CAPABILITY`, `NOOP` and `LOGOUT` are logged as commands |

### Directory & network

| Name | Port | Captures |
|---|---|---|
| `ldap` | `:389` | Credentials (simple bind DN + password) |
| `smb` | `:445` | SMB2 Session Setup: user, domain and workstation, taken only from an NTLMSSP Type 3 message. No password or hash is captured and no challenge is issued. Every Session Setup with a well-formed security buffer counts as an auth attempt (attack), whether or not it carries NTLMSSP |
| `socks5` | `:1080` | Username/password from clients that offer that method, or the `CONNECT` target of clients that offer no authentication |
| `irc` | `:6667` | `PASS` credentials (the username is the `NICK` seen so far) and other commands such as `JOIN`. `NICK`/`USER` registration alone is not logged |

### IoT & industrial

| Name | Port | Captures |
|---|---|---|
| `mqtt` | `:1883` | Credentials (CONNECT client ID + user/pass) |
| `modbus` | `:502` | ICS payloads (function codes + registers) |
| `adb` | `:5555` | ADB CNXN system identity (AUTH token challenge). A first packet that is not CNXN is logged as an `adb_unknown` payload |
| `minecraft` | `:25565` | Handshake metadata + player names from login attempts. A server-list ping (status request) is a probe; only a login with a player name counts as payload |

### UDP

| Name | Port | Captures |
|---|---|---|
| `dns` | `:53` | Query domains + types (responds REFUSED) |
| `snmp` | `:161` | Community string and version (v1/v2c `GetRequest` and `GetNextRequest`) |
| `sip` | `:5060` | Method, `From`/`To` headers and the Digest `username`. The Digest response is not captured, and the credentials counter stays 0 for SIP |
| `ntp` | `:123` | Version and mode of mode 3 client packets; answers with a Kiss-o'-Death `DENY`. `monlist` (mode 7) and other modes only log a `parse_failed` error |

UDP source addresses are spoofable, so UDP traps log and count metrics only.
They never raise CrowdSec alerts (the UDP constructors take no alerter at all).
Inbound packets are rate limited per source and globally (see [Limits](#limits)).
Every UDP packet that passes the rate limiter is its own session with `connect`
and `disconnect` log lines; probe summarization applies to TCP only.

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
Further validation: `RAN_SESSION_TIMEOUT` must be greater than zero;
`RAN_AUTH_DELAY`, `RAN_SSH_TARPIT_DURATION`, `RAN_CROWDSEC_BATCH_INTERVAL` and the
per-trap delay overrides must not be negative; `RAN_<PROTO>_SESSION_TIMEOUT` must be
greater than zero; `RAN_METRICS_ADDR` must be a single `host:port` (no comma list).
A trailing slash on `RAN_CROWDSEC_URL` is trimmed.

Command line helpers:

- `ran check-config` validates the environment without starting the traps. It
  prints the problem and how to fix it and exits 0 (valid) or 1 (invalid). It
  also warns on stderr when a removed variable is still set.
- `ran healthcheck` is the container health check. It exits 1 when the
  configuration is invalid or when `GET /healthz` on the metrics address does
  not answer `200` within 2 seconds (a wildcard host is queried as `127.0.0.1`).
- `ran version` prints the version.

`/healthz` is served on the metrics address next to `/metrics` and returns JSON
with `status`, `version`, `uptime` and the enabled `traps`.

### Authentication behavior and PROXY protocol

<details>
<summary>Retries, delays, SSH tarpit and PROXY protocol</summary>

| Variable | Default | Purpose |
|---|---|---|
| `RAN_MAX_AUTH_RETRIES` | `3` | Credential attempts per session before the trap disconnects (`0` = unlimited until the session timeout). Honored only by `ssh`, `telnet`, `mssql` and `smb` (see below) |
| `RAN_AUTH_DELAY` | `0s` | Delay before answering a failed login; grows up to 4x per attempt. Honored only by `ssh`, `telnet`, `mssql` and `smb` |
| `RAN_SSH_TARPIT` | `off` | Hold SSH clients with slow random banner lines before the SSH handshake (see below) |
| `RAN_SSH_TARPIT_DURATION` | `30s` | Maximum tarpit time per SSH connection (`0s` = no tarpit lines) |
| `RAN_SSH_HOST_KEY_PATH` | `/data/ssh_host_key` | SSH host key file; generated on first start and persisted if the directory is writable (the image declares `/data` as a volume). Otherwise `ran` logs a warning and uses an ephemeral key that changes on every restart; this is not fatal |
| `RAN_HTTPS_CERT_PATH` | `/data/https_cert.pem` | Certificates and keys (one PEM file holding an ECDSA pair and an RSA pair) of the `https` trap; self-signed certificates are generated on first start and written atomically with mode `0600` if the directory is writable. Otherwise (or if the file is unusable, incomplete, expired or not yet valid) `ran` logs a warning and uses ephemeral certificates that change on every restart; this is not fatal |
| `RAN_PROXY_PROTOCOL` | `off` | Require a PROXY v1/v2 header on every TCP connection (see [Threat model](#threat-model)) |
| `RAN_<PROTO>_MAX_AUTH_RETRIES` | | Per-trap override of `RAN_MAX_AUTH_RETRIES` |
| `RAN_<PROTO>_AUTH_DELAY` | | Per-trap override of `RAN_AUTH_DELAY` |
| `RAN_<PROTO>_SESSION_TIMEOUT` | | Per-trap override of `RAN_SESSION_TIMEOUT` |

`<PROTO>` is the upper-case trap name, for example `RAN_SSH_SESSION_TIMEOUT`.

**Which traps honor the retry and delay settings.** `RAN_MAX_AUTH_RETRIES`,
`RAN_AUTH_DELAY` and their `RAN_<PROTO>_` variants apply to `ssh`, `telnet`,
`mssql` and `smb` only. `0` means unlimited attempts until the session timeout
for all four (for `ssh` too: `ran` maps it to an unlimited setting, because
the SSH library would otherwise fall back to 6). The other traps ignore them:

- `ftp`, `pop3`, `imap`, `smtp`, `ldap`, `irc`, `redis`, `http`, `https` and `httpproxy`
  accept unlimited attempts until the session timeout.
- `mysql`, `postgres`, `oracle`, `mqtt`, `rdp`, `vnc` and `socks5` take one
  attempt and then end the session.

**SSH tarpit.** With `RAN_SSH_TARPIT=on` the trap first writes a random 32
character line every 10 seconds, for at most `RAN_SSH_TARPIT_DURATION`, and then
continues with the normal SSH handshake. It is not endless. The tarpit never
outlasts the session: if the tarpit duration is not shorter than the session
timeout (the defaults are both `30s`), it stops slightly before the session
deadline and the session ends with outcome `timeout`. With a shorter tarpit the
session timeout restarts for the handshake.

</details>

### Logging

| Variable | Default | Purpose |
|---|---|---|
| `RAN_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `RAN_LOG_FORMAT` | `json` | Log format: json, text |
| `RAN_LOG_PASSWORDS` | `off` | Password field in credential logs: `off` (omitted), `mask` (`*** (<length>)`), `on` (cleartext) |

Passwords are never sent to CrowdSec, regardless of `RAN_LOG_PASSWORDS`.

### Limits

<details>
<summary>Session, rate and input limits</summary>

| Variable | Default | Purpose |
|---|---|---|
| `RAN_SESSION_TIMEOUT` | `30s` | Max duration of a raw TCP session (Go duration, greater than zero). For `http`, `https`, `elasticsearch` and `httpproxy` it is the read and write timeout of each request (for `https` it also bounds the TLS handshake). Not used by UDP traps |
| `RAN_MAX_SESSIONS` | `500` | Concurrent session limit, global across all TCP and UDP traps |
| `RAN_MAX_PER_IP` | `10` | Per-IP concurrent session limit, global across all TCP and UDP traps |
| `RAN_UDP_RATE_PER_SOURCE` | `20` | UDP packets per second allowed per source address |
| `RAN_UDP_RATE_BURST` | `40` | UDP per-source burst size (must be at least `RAN_UDP_RATE_PER_SOURCE`, otherwise startup fails) |
| `RAN_UDP_RATE_GLOBAL` | `2000` | UDP packets per second allowed across all sources |

Excess UDP packets are dropped before a session is created (logged at debug only,
counted in `ran_udp_rate_limited_total`).
The limiter is per UDP trap, so "global" means per protocol: each of `dns`,
`ntp`, `snmp` and `sip` has its own global bucket. Per-source state is capped
at 100000 sources; once the cap is reached, packets from untracked sources are
only subject to the global bucket.

Input limits (fixed, not configurable):

| Trap | Limit |
|---|---|
| `ftp`, `smtp`, `irc` | 512 byte lines |
| `pop3`, `imap` | 1024 byte lines |
| `telnet`, `redis` (inline commands), `memcached` | 4096 byte lines |
| `redis` (RESP) | 128 arguments, 4096 bytes per bulk string |
| `ldap` | 64 KiB per BER element |
| `mysql`, `postgres`, `mqtt`, `smb` | 1 MiB per packet |
| `mssql`, `oracle` | 64 KiB per packet (the length field has 16 bits) |
| `minecraft` | 32767 bytes per packet |
| `http`, `https` | 16 KiB for the request body and for the headers; logged values and `path`/`user_agent` meta 256 bytes |
| `https` (ClientHello) | first TLS record only (at most 16 KiB captured); 256 cipher suites, 128 extensions, 64 groups, 16 point formats, 128 signature algorithms, 32 versions and 16 ALPN entries; SNI 256 bytes |
| `adb` | 4096 bytes of identity data |
| `rdp` | 1024 bytes per TPKT packet |
| UDP traps | 4096 bytes per packet (the rest is cut off) |

On SIGTERM or SIGINT the listeners close and live sessions are closed at once
(they are not drained). Shutdown shares one 9 second deadline, below Docker's
default 10 second stop grace period regardless of `RAN_SESSION_TIMEOUT`: traps
and the metrics server get 4 seconds, then the CrowdSec sink drains its queue
within the remaining time (at most 5 seconds, with one last attempt if the
LAPI was failing). If every trap exits on its own while nothing asked to stop,
`ran` logs an error and exits with code 1 so the runtime restarts it.

</details>

### Metrics

<details>
<summary>Exposed metrics</summary>

| Variable | Default | Purpose |
|---|---|---|
| `RAN_METRICS_ADDR` | `:9550` | Prometheus metrics listen address (a single `host:port`; also serves `/healthz`) |

Exposed metrics, besides `ran_build_info{version,goversion}` and the standard Go
runtime and process collectors:

- `ran_connections_total{protocol,outcome}`: connection counter. Outcomes: `completed`, `timeout`, `error`, `too_long` (line over the read limit), `probe` (the client did not speak the protocol)
- `ran_credentials_captured_total{protocol}`: credential capture counter
- `ran_active_sessions{protocol}`: active session gauge
- `ran_session_duration_seconds{protocol}`: session duration histogram (buckets 0.1 s to 120 s)
- `ran_crowdsec_alerts_dropped_total{protocol}`: alerts dropped because the delivery queue was full
- `ran_panics_recovered_total{protocol}`: panics recovered at connection and packet boundaries
- `ran_proxy_protocol_dropped_total{protocol}`: connections closed by the PROXY protocol listener (no valid header, deadline, handshake limit, stalled consumer)
- `ran_udp_rate_limited_total{protocol}`: UDP packets dropped by the packet rate limiter
- `ran_sessions_rejected_total{protocol}`: TCP connections and UDP packets rejected by the session limiter (`RAN_MAX_SESSIONS`, `RAN_MAX_PER_IP`)
- `ran_probe_summary_suppressed_sessions_total`: probe sessions whose per-session log lines were replaced by a summary
- `ran_tracked_entries{map}`: entries in the bounded tracking maps (`map`: `scan`, `probe`, `cooldown`)
- `ran_tracked_evictions_total{map}`: live entries evicted because a map was full; a rising rate means `RAN_CROWDSEC_MAX_TRACKED` is too small
- `ran_crowdsec_push_duration_seconds`: histogram of CrowdSec LAPI push request durations
- `ran_crowdsec_push_errors_total`: failed LAPI pushes (transport errors, non-2xx answers and failed re-logins after a 401)
- `ran_crowdsec_queue_length`: alerts waiting in the send queue
- `ran_crowdsec_pipeline_total{protocol,stage}`: CrowdSec alert pipeline events. Stages: `received`, `invalid` (rejected source address), `closed` (raised after shutdown), `filtered` (class not in `RAN_BAN_ON`), `cooldown` (within `RAN_ALERT_COOLDOWN`), `queued`, `dropped`, `sent`, `failed`, `released` (cooldown slot freed after a failed push, so the source is reported again). The 0.3.x stages `cached` and `deduplicated` no longer exist. Per-class counts are not a label (cardinality); the class is in the alert meta and the logs.

</details>

### CrowdSec

rán is a sensor: it classifies every TCP session, aggregates the noise and
pushes alerts to the CrowdSec LAPI. **rán does not ban anything by itself.**
Alerts carry no decisions; a CrowdSec profile decides whether and for how long
an IP is banned (see [Escalation with CrowdSec profiles](#escalation-with-crowdsec-profiles)).
Without a profile nothing is banned.

| Variable | Default | Purpose |
|---|---|---|
| `RAN_CROWDSEC` | `off` | Enable CrowdSec LAPI alerting |
| `RAN_CROWDSEC_URL` | | CrowdSec LAPI URL (required when enabled). Trailing slashes are trimmed |
| `RAN_CROWDSEC_MACHINE_ID` | | Machine ID for LAPI login (required when enabled) |
| `RAN_CROWDSEC_PASSWORD` | | Machine password for LAPI login (required when enabled) |
| `RAN_BAN_ON` | `attack,scan` | Classes that produce a CrowdSec alert (subset of `probe,attack,scan`). `probe` stays in logs and metrics only unless listed. If `scan` is not listed, a scan-classified session is reported as its own class instead (attack if it did something, otherwise probe, which is then filtered) |
| `RAN_ALERT_COOLDOWN` | `1h` | At most one alert per IP and class per cooldown (`0s` = disabled) |
| `RAN_PROBE_SUMMARY_WINDOW` | `60s` | Window of the aggregated probe summary log line (`0s` = one log line per probe session) |
| `RAN_CROWDSEC_BATCH_INTERVAL` | `10s` | Batch flush interval (`0s` = immediate, one POST per alert, no batching) |
| `RAN_CROWDSEC_BATCH_SIZE` | `50` | Max alerts per batch POST (a batch is also flushed early at about 512 KiB) |
| `RAN_CROWDSEC_MAX_TRACKED` | `20000` | Cap of each of the three in-memory maps separately: alert cooldown, scan tracker and probe summaries (see sizing below) |

`RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and
`RAN_CROWDSEC_DEDUP_WINDOW` were removed in 0.4.0. They are ignored; rán logs a
one-time warning at startup if one is still set.

<details>
<summary>Delivery, failures and memory sizing</summary>

**Delivery and failures.** On startup `ran` logs in to the LAPI; if that first
login fails, `ran` exits with code 1. Later outages are handled at runtime: alerts
wait in a queue of 256 (more are dropped and counted), a failed push pauses the
sender for `max(RAN_CROWDSEC_BATCH_INTERVAL, 1s)`, and a `401` triggers one
re-login. A failed batch is not retried; its cooldown slots are released so the
next qualifying session of each source is reported again. One flush is bounded
to 5 seconds and the HTTP client timeout is 10 seconds. The token is refreshed
in the background; a failed refresh is retried with backoff.

**Memory sizing.** Each of the three maps (cooldown, scan tracker, probe summaries)
has its own cap of `RAN_CROWDSEC_MAX_TRACKED` entries, and an entry costs about
400 bytes, so with the default all three full are roughly 25 MB (3 x 20000 x 400
bytes). The scan and probe maps are active even with `RAN_CROWDSEC=off`; the cooldown
map exists only with CrowdSec enabled. The UDP rate limiter keeps a separate
per-source map (up to 100000 sources per UDP trap) that is not part of this
estimate. A 1M unique-source flood peaked at 227 MB heap with a cap of 100000. Size
the container memory limit for the cap you choose, and set `GOMEMLIMIT` to about 80
percent of the container limit (for example `GOMEMLIMIT=100MiB` for a 128 MB limit)
so the garbage collector works harder before the kernel OOM-kills the process.

</details>

#### Classification

<details>
<summary>Classes, scan detection and alert payload</summary>

| Class | Meaning |
|---|---|
| `probe` | Connect and banner only: no auth attempt, command or payload byte |
| `attack` | At least one auth attempt, command or payload byte |
| `scan` | The same source IP touched at least 3 distinct TCP trap protocols within about 10 minutes |

Scan detection never counts UDP (spoofable) or non-public source addresses, and
its in-memory map is capped (oldest entries are evicted first, which only delays
a scan classification). A scan is always its own alert, even if the session that
crossed the threshold was only a probe; its scenario uses the protocol that
crossed it. `scan` outranks `attack`, which outranks `probe`. The scan and
probe maps are active even with `RAN_CROWDSEC=off`.

Classes are only downgraded in one case: if `scan` is not in `RAN_BAN_ON`, a
scan-classified session is evaluated as its own class (attack if it logged an
auth attempt, command or payload, otherwise probe), so a scanner that also
attacks still produces attack alerts. Keep `scan` in the list if you want scan
alerts.

**Alert payload.** One alert is pushed per qualifying event, with scenario
`custom/ran-<protocol>-trap` for every class, `events_count` 1, `capacity` 0,
`leakspeed` `"0"`, `simulated` false, `remediation` true, no decisions, and
exactly one event. `source.ip` and `source.value` are both set (geo enrichment
keeps working). The event meta contains the sensor keys `class`, `protocol`,
`dest_port`, `auth_attempts`, `commands` and `payload_bytes`, plus trap-specific
keys where the trap has them (for example `username`, the command name, `path`,
`target`, `identity`, `client_id`, `service_name`, `domain`, `workstation`,
`function_code`, `player_name`). The meta is bounded:

- keys named `password`, `pass`, `passwd`, `secret`, `token` or `authorization`
  (case-insensitive) are dropped, so passwords never leave the host;
- at most 32 keys (sensor keys always survive, surplus trap keys are dropped in
  sorted order), keys cut to 64 bytes and values to 256 bytes, with control and
  format characters replaced by a space.

Scan and escalation alerts raised at session end carry only the sensor keys.

Sessions are classified from the counters when they end, so a trap that logs a
command, payload or auth attempt ends as `attack` even if it did not alert
mid-session (redis, memcached, imap and irc alert on the first command with only
the command name as meta). Pure fingerprinting stays a `probe`: Elasticsearch
plain GET requests without a body, HTTP `GET`/`HEAD` requests that match no exploit path or JNDI string, and Minecraft server-list pings. Per-trap
tuning for single-request protocols (a modbus request, an ADB CONNECT) is a
planned follow-up.

</details>

#### Logging of probes

<details>
<summary>Probe log summaries</summary>

TCP probe sessions are not logged one by one. Per source IP and
`RAN_PROBE_SUMMARY_WINDOW` rán writes one summary line
(`action: probe_summary`, `sessions`, `protocols`). Attack and scan sessions keep
their full per-event lines (credentials, commands, payloads). A probe session that
triggers a scan alert is still summarized in the logs. UDP sessions are never
summarized: they always log `connect` and `disconnect` lines. The `ran_*`
metrics are still updated per session, so dashboards are unaffected.

</details>

#### Alert pipeline

<details>
<summary>Pipeline, cooldown and address validation</summary>

```
trap session ──▶ Classify (probe / attack / scan) ──▶ Alert pipeline ──▶ POST /v1/alerts
                                                       │
   IP validation ─▶ class filter (RAN_BAN_ON) ─▶ cooldown ─▶ batch queue
        invalid          filtered                  cooldown       queued / dropped
```

1. **IP validation**: addresses in a denylist of non-global ranges are dropped
   (stage `invalid`, see below).
2. **Class filter**: classes not in `RAN_BAN_ON` stop here (stage `filtered`).
3. **Cooldown**: the same class, or any higher class, still cooling down for an
   IP suppresses the alert for the full `RAN_ALERT_COOLDOWN` (stage `cooldown`),
   regardless of how long the resulting ban lasts. A move to a higher class (probe
   to attack, attack to scan) passes once. The cooldown is keyed per IP and class,
   so one IP holds up to 3 entries. The slot is only consumed when the alert is
   queued; if the queue is full the alert is dropped and may be retried. With the
   default 1h cooldown a continuous attacker produces about one alert per hour,
   equal to the shortest ban step of the example profile below, so bans renew
   without a gap and CrowdSec's `GetDecisionsCount` counts episodes, not packets.
   Raising the cooldown reduces alert volume but leaves a renewal gap for every
   ban step shorter than the cooldown (the attacker is unbanned until the next
   alert). Compared with the former 4h default expect roughly 2 to 4 times more
   alerts and faster escalation (1h, 3h, 9h and so on). `0s` disables the cooldown.
4. **Batch queue**: alerts are flushed as one POST on a timer or at the batch size.

When a map is full, the oldest entries are evicted. An evicted cooldown entry can
alert again, so a full map means more LAPI traffic.

Only the TCP peer address is used as alert identity. The HTTP trap logs
`X-Real-IP` / `X-Forwarded-For` as `claimed_client_ip` but never alerts on it
(behind a trusted proxy, use `RAN_PROXY_PROTOCOL`). Address validation is a
denylist, not a positive test for publicly routable addresses. IPv4-mapped IPv6
addresses are unmapped first, zoned addresses are rejected, and these ranges are
dropped:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT), `127.0.0.0/8`,
  `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`,
  `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`,
  `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`.
- IPv6: `::/128`, `::1/128`, `::ffff:0:0/96`, `::/96`, `64:ff9b::/96`,
  `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `2002::/16`,
  `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `ff00::/8`.

LAN-only deployments therefore produce no CrowdSec alerts.

With `RAN_PROXY_PROTOCOL`, the PROXY v1 or v2 header is required. A connection
must send a valid header within 3 seconds; a connection that sends other bytes,
closes early or stays silent is closed and counted in
`ran_proxy_protocol_dropped_total`, never handled as a plain connection. A
silent peer does not block other clients. At most 1024 connections per listen
address may be waiting for a header (or for the trap to take them) at once;
further ones are closed immediately and counted too. The mode applies to all TCP
traps and never to UDP. `PROXY ... UNKNOWN` (v1) and `LOCAL` (v2) headers keep
the address of the proxy itself. Only enable this mode when ran is reachable
solely from a trusted proxy or tunnel: a forged header lets any peer that can
connect directly choose the source address ran reports, so any public IP can be
reported and then banned. A source allowlist for trusted proxies is a possible
future change.

</details>

#### Connecting rán to CrowdSec

Register the machine before starting rán:

```bash
cscli machines add ran-honeypot --password <password>
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
      RAN_ALERT_COOLDOWN: 1h
```

#### Escalation with CrowdSec profiles

<details>
<summary>Example profiles and ban escalation</summary>

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

</details>

#### CrowdSec behaviors to know

<details>
<summary>CAPI sharing, allowlists and alert history</summary>

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

</details>

#### Migrating from 0.3.x

<details>
<summary>Upgrade notes</summary>

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

Behavior changes after 0.4.0: the default of `RAN_ALERT_COOLDOWN` changed from
`4h` to `1h` (set `RAN_ALERT_COOLDOWN=4h` to keep the old volume; see the
cooldown notes above). `RAN_MAX_AUTH_RETRIES=0` is now really unlimited for `ssh`
(it used to fall back to 6 attempts). Negative durations, a comma separated
`RAN_METRICS_ADDR` and a zero `RAN_SESSION_TIMEOUT` are now rejected at startup,
and with `scan` missing from `RAN_BAN_ON` a scanner's attacks are reported as
attack instead of being dropped.

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

</details>

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
- **TLS fingerprints are claims.** The `https` trap records SNI, JA3 and JA4 of
  the ClientHello as alert meta. They are client controlled (any client can
  send any SNI or mimic a fingerprint), so they are context for triage, never
  identity. The certificate is self-signed with `CN=localhost` and imitates no
  real host. The key is generated per instance and is not meant to be reused. To accept old scanners the trap deliberately weakens its TLS: minimum version TLS 1.0 and all cipher suites Go implements (no `GODEBUG` setting is needed, because an explicit `MinVersion` and `CipherSuites` override the defaults that `tls10server`, `tlsrsakex` and `tls3des` control). Negotiated sessions are therefore not confidential; the traffic is attacker traffic by definition.
- **Detectability.** Banners are generic and plausible, but a determined
  attacker can fingerprint any honeypot. Do not rely on rán staying hidden.
- **Isolation.** Run it unprivileged, without capabilities and with a read-only
  filesystem (see below). Never place it on a network segment with sensitive
  hosts.

### Recommended container settings

<details>
<summary>Hardened compose example</summary>

The image runs as user `65532` and needs write access only to `/data` (the SSH host key and the HTTPS certificate). Docker sets `net.ipv4.ip_unprivileged_port_start=0` inside containers, so
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
      - ran-data:/data            # SSH host key, HTTPS certificate
    tmpfs:
      - /tmp
volumes:
  ran-data:
```

Sizing: memory is dominated by the tracking maps (see *Memory sizing* above) and
by concurrent sessions (`RAN_MAX_SESSIONS`). Set `GOMEMLIMIT` to about 80
percent of the container limit.

</details>

## Log format

<details>
<summary>Log line format and actions</summary>

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

Actions: `connect`, `auth_attempt`, `command`, `payload`, `disconnect`,
`probe_summary`, `probe` (fingerprinting events that do not count as an attack),
`rejected` (session limiter) and `error`. TCP connect and disconnect lines are
written for sessions that do something; TCP probe sessions are summarized (see
[Logging of probes](#logging-of-probes)). UDP traps always log `connect` and
`disconnect`.

</details>

## Troubleshooting

<details>
<summary>Common problems</summary>

**`at least one trap must be enabled`**: set `RAN_TRAPS` to a comma-separated
list of traps. `ran check-config` validates the whole configuration.

**Port already in use**: another service is on the default port. The failing
trap logs `trap failed to start` and is skipped while the others keep running;
`ran` exits with code 1 only if all traps fail or the metrics address cannot be
bound. Override the port with `RAN_<PROTO>_ADDR=:<port>` (or `RAN_METRICS_ADDR`).

**CrowdSec alerts not arriving**: verify `RAN_CROWDSEC_URL` is reachable
from the container (without a trailing slash; it is trimmed anyway) and the
machine is registered (`cscli machines list`). With `RAN_CROWDSEC=on` a failed
first LAPI login is fatal (exit code 1); later outages are retried as described
under [CrowdSec](#crowdsec). Check `ran_crowdsec_push_errors_total` and
`ran_crowdsec_pipeline_total{stage="failed"}`.

**Alerts arrive but nothing is banned**: rán does not create decisions. Add a
CrowdSec profile for the `attack` and `scan` classes (see
[Escalation with CrowdSec profiles](#escalation-with-crowdsec-profiles)).

**UDP traps not receiving packets**: Docker needs explicit UDP port mapping:
`-p 53:53/udp`, not just `-p 53:53`.

**High connection volume causing drops**: increase `RAN_MAX_SESSIONS` and
`RAN_MAX_PER_IP`, or enable only the traps you need.

</details>

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
