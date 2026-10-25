# Configuration

## Trap selection

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

Binding is all or nothing: if one address of a multi-port trap cannot be bound
(already in use, or a privileged port without permission), the trap does not
start at all and the other ports are released. This also holds for the `telnet`
default `:23,:2323`; if only one of them is available, set
`RAN_TELNET_ADDR` to that port (for example `RAN_TELNET_ADDR=:2323`).

Listen addresses are validated at startup (`host:port` or `:port`, port 1 to 65535).
Further validation: `RAN_SESSION_TIMEOUT` must be greater than zero;
`RAN_AUTH_DELAY`, `RAN_SSH_TARPIT_DURATION`, `RAN_CROWDSEC_BATCH_INTERVAL` and the
per-trap delay overrides must not be negative; `RAN_<PROTO>_SESSION_TIMEOUT` must be
greater than zero; `RAN_METRICS_ADDR` must be a single `host:port` (no comma list).
A trailing slash on `RAN_CROWDSEC_URL` is trimmed.

## Catch-all and banner traps

| Variable | Default | Purpose |
|---|---|---|
| `RAN_CATCHALL_ADDR` | | Required when `catchall` is enabled. Comma-separated listen addresses (`:4444,:6000`), validated like every other `RAN_<PROTO>_ADDR` |
| `RAN_BANNER_SERVICES` | | Required when `banner` is enabled. Comma-separated `port=name:banner` entries, at most 10 |

`RAN_BANNER_SERVICES` rules: the port is 1 to 65535 and unique, the name uses
`a-z`, `0-9`, `_` and `-` (at most 32 bytes), and the banner is 1 to 256 bytes
after escapes. The escapes `\r`, `\n`, `\t`, `\\` and `\,` (a literal comma) are
interpreted; any other backslash sequence is an error. The first `:` after the
name starts the banner, so the banner may contain colons. Every problem is
reported by `ran check-config` with the offending entry.

```bash
RAN_TRAPS=ssh,catchall,banner
RAN_CATCHALL_ADDR=:4444,:6000
RAN_BANNER_SERVICES=9999=custom:hello\r\n,7000=fake-ftp:220 FTP ready\r\n
```

Routing: `ran` only listens. It does not install iptables or nftables rules, does
not redirect ports and uses no raw sockets. Publish the ports to the container
(`-p 4444:4444`) or redirect them on the host yourself; the container image
exposes no catch-all or banner ports because they have no defaults.

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

## Authentication behavior and PROXY protocol


| Variable | Default | Purpose |
|---|---|---|
| `RAN_MAX_AUTH_RETRIES` | `3` | Credential attempts per session before the trap disconnects (`0` = unlimited until the session timeout). Honored only by `ssh`, `telnet`, `mssql`, `smb`, `mysql` and `postgres` (see below) |
| `RAN_AUTH_DELAY` | `0s` | Delay before answering a failed login; grows up to 4x per attempt. Honored only by `ssh`, `telnet`, `mssql`, `smb`, `mysql` and `postgres` |
| `RAN_SSH_TARPIT` | `off` | Hold SSH clients with slow random banner lines before the SSH handshake (see below) |
| `RAN_SSH_TARPIT_DURATION` | `30s` | Maximum tarpit time per SSH connection (`0s` = no tarpit lines) |
| `RAN_SSH_HOST_KEY_PATH` | `/data/ssh_host_key` | SSH host key file; generated on first start and persisted if the directory is writable (the image declares `/data` as a volume). Otherwise `ran` logs a warning and uses an ephemeral key that changes on every restart; this is not fatal |
| `RAN_HTTPS_CERT_PATH` | `/data/https_cert.pem` | Certificates and keys (one PEM file holding an ECDSA pair and an RSA pair) of the `https` trap; self-signed certificates are generated on first start and written atomically with mode `0600` if the directory is writable. Otherwise (or if the file is unusable, incomplete, expired or not yet valid) `ran` logs a warning and uses ephemeral certificates that change on every restart; this is not fatal |
| `RAN_FINGERPRINT` | `seeded` | Version strings the traps present (SSH, MySQL, HTTP, SMTP, Elasticsearch): `seeded` picks plausible values from built-in sets with a persisted seed, `fixed` keeps the fixed values of earlier releases (see [Banner profiles](/configuration#banner-profiles)). Any other value is a configuration error |
| `RAN_FINGERPRINT_SEED_PATH` | `/data/fingerprint_seed` | File that persists the 32 byte seed (hex), written atomically with mode `0600` on first start if the directory is writable. Otherwise (or if the file is unreadable, corrupt or short) `ran` logs a warning and uses an ephemeral seed, so the banners change on every restart; this is not fatal. Unused with `RAN_FINGERPRINT=fixed` |
| `RAN_HTTP_FIXTURES` | | Path of a JSON file with operator fixtures for the `http` and `https` traps (see [HTTP fixtures](/configuration#http-fixtures)); read once at startup and validated by `ran check-config`. Unset: only the built-in fixtures |
| `RAN_PROXY_PROTOCOL` | `off` | Require a PROXY v1/v2 header on every TCP connection (see [Threat model](/hardening#threat-model)); requires `RAN_PROXY_TRUSTED` |
| `RAN_PROXY_TRUSTED` | | Peers allowed to send PROXY headers: comma-separated IPs and CIDRs (IPv4/IPv6, same format as `RAN_IGNORE_IPS`, at most 1024 entries), for example `10.0.0.0/8,2001:db8::/32`, or the single value `any`. Required (startup fails without it) when `RAN_PROXY_PROTOCOL=on`; `any` trusts every peer and logs a warning. With the protocol off the value is ignored with a warning. See [PROXY protocol trust](/hardening#threat-model) |
| `RAN_<PROTO>_MAX_AUTH_RETRIES` | | Per-trap override of `RAN_MAX_AUTH_RETRIES` |
| `RAN_<PROTO>_AUTH_DELAY` | | Per-trap override of `RAN_AUTH_DELAY` |
| `RAN_<PROTO>_SESSION_TIMEOUT` | | Per-trap override of `RAN_SESSION_TIMEOUT` |

`<PROTO>` is the upper-case trap name, for example `RAN_SSH_SESSION_TIMEOUT`.

**Which traps honor the retry and delay settings.** `RAN_MAX_AUTH_RETRIES`,
`RAN_AUTH_DELAY` and their `RAN_<PROTO>_` variants apply to `ssh`, `telnet`,
`mssql`, `smb`, `mysql` and `postgres` only. `0` means unlimited attempts until the session timeout
for all six (for `ssh` too: `ran` maps it to an unlimited setting, because
the SSH library would otherwise fall back to 6). For `ssh` every rejected password, keyboard-interactive and distinct public-key offer counts as one attempt. The other traps ignore them:

- `ftp`, `pop3`, `imap`, `smtp`, `ldap`, `irc`, `redis`, `http`, `https` and `httpproxy`
  accept unlimited attempts until the session timeout.
- `oracle`, `mqtt`, `rdp`, `vnc` and `socks5` take one
  attempt and then end the session. `rdp` cannot retry by design: the only user name
  is in the X.224 cookie and the negotiation failure ends the exchange.
- `mysql` asks for another password with an authentication switch to
  `mysql_clear_password`; `postgres` repeats the cleartext password request
  (without an error in between). A client that does not answer ends the session
  after the attempts it made. A password identical to the previous attempt of
  the session (clients such as libpq and pgx resend the stored password) is not
  a new attempt: it is not logged again and the session ends. `mysql` sends the
  authentication switch only to clients that set `CLIENT_PLUGIN_AUTH` and
  answers all others with the error immediately.

**SSH tarpit.** With `RAN_SSH_TARPIT=on` the trap first writes a random 32
character line every 10 seconds, for at most `RAN_SSH_TARPIT_DURATION`, and then
continues with the normal SSH handshake. It is not endless. The tarpit never
outlasts the session: if the tarpit duration is not shorter than the session
timeout (the defaults are both `30s`), it stops slightly before the session
deadline and the session ends with outcome `timeout`. With a shorter tarpit the
session timeout restarts for the handshake.


## HTTP fixtures

The `http` and `https` traps answer `GET` and `HEAD` requests for a small built-in set of paths with static, invented product-like content, so scanners that look for a specific product see a confirming answer and keep sending requests: `/.git/HEAD`, `/.git/config`, `/.env`, `/actuator/health`, `/actuator/env`, `/server-status`, `/phpinfo.php`, `/wp-json/`, `/robots.txt`, `/sitemap.xml` and `/.well-known/security.txt`. Matching is on the exact request path (case sensitive, the query is ignored). Bodies are static and never contain any part of the request. Logging and classification happen before the answer exactly as without fixtures, so exploit paths such as `/.env`, `/actuator/env`, `/phpinfo.php` and `/server-status` stay commands (`attack`) and ordinary paths such as `/robots.txt` stay a `probe`. `HEAD` returns the status and headers (with `Content-Length`) and no body. `POST`, `PUT`, `PATCH` and every other method keep the normal behavior, so form logins on a fixture path are still captured and answered with the login error page. `docker`, `kubernetes` and `mcp` are not affected.

`RAN_HTTP_FIXTURES` names a JSON file with your own fixtures. They take precedence over built-in ones with the same path. The file is read once at startup and validated by `ran check-config` (an error names the entry). It is only read when `http` or `https` is enabled.

```json
{"fixtures": [
  {"path": "/status", "status": 200,
   "headers": {"Content-Type": "application/json"},
   "body": "{\"state\":\"ok\"}"}
]}
```

Limits: at least 1 and at most 64 entries (an empty `fixtures` list is rejected), bodies up to 8 KiB, a file up to 1 MiB, paths up to 256 bytes (start with `/`, printable ASCII, no spaces, `?`, `#` or `%`; requests are matched on the decoded path, so write `/a b`-style paths decoded, never as `%2f`), unique paths, at most 16 headers of up to 256 printable ASCII bytes. Unknown fields and duplicate JSON keys (in the top-level object, an entry or a headers map) are rejected. `status` defaults to `200` and must be one of `200`, `204` (empty body), `400`, `401`, `403`, `404`, `500`, `503`. Allowed headers: `Content-Type` (default `text/plain; charset=utf-8`), `Cache-Control`, `Content-Language`, `ETag`, `Expires`, `Last-Modified`, `Server`, `X-Powered-By`, `X-Content-Type-Options`, `X-Frame-Options`, `X-Robots-Tag`, `Link`, `Allow`, `WWW-Authenticate`. There is no templating and no reload at runtime.

## Banner profiles


A fleet of sensors that all say `OpenSSH_9.6`, MySQL `8.0.36` and `Apache/2.4.62`
is easy to recognize and filter. With `RAN_FINGERPRINT=seeded` (the default) each
instance picks its version strings from small built-in sets of plausible values
(OpenSSH with the distribution suffix real packages carry, MySQL 5.7 and 8.0 patch
levels, Apache and nginx `Server` headers with the PHP version of the same
distribution release, SMTP greetings with host names from the documentation
domains `example.com`, `example.net` and `example.org`, Elasticsearch versions
with a matching cluster and node name). The choice is derived from a random
32 byte seed that is generated once and persisted at `RAN_FINGERPRINT_SEED_PATH`
(next to the SSH host key in `/data`). The same seed always gives the same
banners, so a restart keeps them; instances with different seeds differ. Banners
are never random per connection.

- The `Server` and `X-Powered-By` headers are identical on `http`, `https` and the
  built-in fixtures. With an nginx profile `/server-status` is not served (nginx
  has no such page) and falls back to the login page.
- Each trap chooses independently from the seed; the values of one trap agree with
  each other (for example the `Server` header, the PHP version and the
  `/server-status` page), but SSH and HTTP may name different distributions.
- SSH: the key exchange, cipher and MAC lists are limited to what OpenSSH 8.2 to
  9.6 offered and the Go SSH library implements (no `mlkem768x25519-sha256`,
  which OpenSSH added in 9.9; also no `sntrup761x25519-sha512@openssh.com`, the
  umac MACs or `diffie-hellman-group18-sha512`, which the library lacks). The host
  key is ed25519 only, whereas OpenSSH also offers RSA and ECDSA keys, so the
  algorithm list still differs from a real server.
- MySQL: in seeded mode the greeting follows the profile's generation. 8.0.x
  advertises `caching_sha2_password` and charset `utf8mb4_0900_ai_ci`, 5.7.x
  `mysql_native_password` and `latin1_swedish_ci`, with capability flags of a
  server without TLS. The password is still captured: after the client's scramble
  the trap asks for it with an authentication switch to `mysql_clear_password`
  (the scramble itself is not recorded as a credential; clients that refuse the switch or hang up count as one login attempt with the username only, and the switch round does not use up `RAN_MAX_AUTH_RETRIES`). `fixed` mode keeps the
  old greeting.
- `/phpinfo.php` shows the distribution's PHP package version and a kernel that
  fits the distribution; Elasticsearch root documents carry the build fields of
  their version (Lucene and compatibility versions follow the real releases, build
  hashes and dates are plausible placeholders) and `X-elastic-product` is sent
  from 7.14 on. `fixed` mode keeps the earlier output.
- If the seed cannot be persisted (read-only or root-owned volume) `ran` logs a
  warning and uses an ephemeral seed: the banners then change on every restart.
- `RAN_FINGERPRINT=fixed` keeps the values of earlier releases
  (`SSH-2.0-OpenSSH_9.6`, MySQL `8.0.36`, `Apache/2.4.62` with `PHP/8.3.6`,
  `220 mx.localdomain ESMTP ready`, Elasticsearch `8.12.0`) and never touches the
  seed file. Use it if you parse the banners.

This varies the surface, it does not hide the honeypot (see the
[threat model](/hardening#threat-model)).


## Logging

| Variable | Default | Purpose |
|---|---|---|
| `RAN_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `RAN_LOG_FORMAT` | `json` | Log format: json, text |
| `RAN_LOG_PASSWORDS` | `off` | Password field in credential logs: `off` (omitted), `mask` (`*** (<length>)`), `on` (cleartext). Also gates the raw `catchall` bytes (`hex`, `text`) and credential lines of the `banner` trap |

Passwords are never sent to CrowdSec, regardless of `RAN_LOG_PASSWORDS`.

## Ignore list

| Variable | Default | Purpose |
|---|---|---|
| `RAN_IGNORE_IPS` | | Comma-separated IP addresses and CIDR ranges (IPv4 and IPv6) whose sessions never alert. At most 1024 distinct entries. Invalid entries or a longer list fail startup and `ran check-config` and name the entry or the limit |

Use it for your own monitoring, scanners and admin hosts. A session from an
ignored source is still served, logged with `ignored=true`, counted in the
connection metrics and in `ran_ignored_sessions_total`, and it still counts
against `RAN_MAX_SESSIONS` and `RAN_MAX_PER_IP`. It never raises an alert, never
enters the scan tracker and never enters the probe summary (its probe sessions
keep their per-session log lines). IPv4-mapped IPv6 peers (`::ffff:8.8.8.8`) match
their IPv4 entry. With `RAN_PROXY_PROTOCOL` on, the address from the PROXY header
is matched. UDP traps never alert anyway; for them the list only adds
`ignored=true` to the log lines and counts the metric. The list is read once at
startup (no reload) and the startup log reports the number of ranges. A very
wide range (a prefix shorter than /8, such as `0.0.0.0/0` or `::/0`) is accepted but
logged as a warning at startup and printed by `ran check-config` on stderr.

## Limits


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
| `telnet`, `redis` (inline commands), `memcached` | 4096 byte lines. `telnet` answers at most 192 bytes of option negotiation per line and keeps 64 bytes of terminal type |
| `redis` (RESP) | 128 arguments, 4096 bytes per bulk string |
| `ldap` | 64 KiB per BER element |
| `mysql`, `postgres`, `mqtt`, `smb` | 1 MiB per packet |
| `mssql`, `oracle` | 64 KiB per packet (the length field has 16 bits) |
| `minecraft` | 32767 bytes per packet |
| `http`, `https`, `docker`, `kubernetes`, `mcp` | 16 KiB for the request body and for the headers; logged values and `path`/`user_agent` meta 256 bytes. `docker` keeps at most 64 command words and 1024 bytes before the 256 byte cut; `kubernetes` 32 values |
| `mcp` (JSON-RPC) | batch of at most 16 messages; method, tool and client names 64 bytes; at most 8 argument keys of 64 bytes each and 128 bytes per string value (summary at most 1552 bytes in the log, 256 bytes as `command` meta); JSON nesting is bounded by the 16 KiB body (the decoder itself refuses more than 10000 levels); ids as described in the trap table |
| `mongodb` | 64 KiB per message (the protocol allows 48 MB; larger messages close the connection before anything is read); first 64 top-level BSON elements of the command document, nested documents are skipped by their declared length; user names 128 bytes |
| `https` (ClientHello) | first TLS record only (at most 16 KiB captured); 256 cipher suites, 128 extensions, 64 groups, 16 point formats, 128 signature algorithms, 32 versions and 16 ALPN entries; SNI 256 bytes |
| `adb` | 4096 bytes of identity data and 4096 bytes per later packet (a longer declared length ends the session), 8 packets after the token, command meta 256 bytes |
| `rdp` | 1024 bytes per TPKT packet |
| `s7comm` | 1024 bytes per TPKT packet (a longer declared length ends the session before it is read), 64 packets per session |
| `enip` | 24 byte header and at most 1024 bytes of data per packet (a longer declared length ends the session), 64 packets per session |
| `pjl` | 1024 bytes per read unit (a line or a block of binary data), 64 KiB per session, 64 PJL commands per session; print data is summarized (length, 16 hex characters of SHA-256, 64 printable bytes), never stored |
| `ipp` | 16 KiB for the request body and for the headers; at most 64 attributes inspected per request, attribute names 255 bytes, job name 64 bytes; the document is only counted, never stored (`document_bytes` is the number of bytes read after the end-of-attributes tag; for a body cut at 16 KiB it is the declared `Content-Length` minus the attribute bytes, capped at 2 GiB, and a chunked body has no declared length, so it is understated to what was read) |
| `catchall` | one read of at most 256 bytes, within a 3 second window (cut to the session timeout); nothing else is read |
| `banner` | 512 byte lines, at most 100 lines per connection; banners are at most 256 bytes and there are at most 10 services |
| UDP traps | 4096 bytes per packet (the rest is cut off) |

On SIGTERM or SIGINT the listeners close and live sessions are closed at once
(they are not drained). Shutdown shares one 9 second deadline, below Docker's
default 10 second stop grace period regardless of `RAN_SESSION_TIMEOUT`: traps
and the metrics server get 4 seconds, then the CrowdSec sink drains its queue
within the remaining time (at most 5 seconds, with one last attempt if the
LAPI was failing). If every trap exits on its own while nothing asked to stop,
`ran` logs an error and exits with code 1 so the runtime restarts it.

