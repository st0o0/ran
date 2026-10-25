# CrowdSec

rán is a sensor: it classifies every TCP session, aggregates the noise and
pushes alerts to the CrowdSec LAPI. **rán does not ban anything by itself.**
Alerts carry no decisions; a CrowdSec profile decides whether and for how long
an IP is banned (see [Escalation with CrowdSec profiles](/crowdsec#escalation-with-crowdsec-profiles)).
Without a profile nothing is banned.

| Variable | Default | Purpose |
|---|---|---|
| `RAN_CROWDSEC` | `off` | Enable CrowdSec LAPI alerting |
| `RAN_CROWDSEC_URL` | | CrowdSec LAPI URL (required when enabled). Trailing slashes are trimmed |
| `RAN_CROWDSEC_MACHINE_ID` | | Machine ID for LAPI login (required when enabled) |
| `RAN_CROWDSEC_PASSWORD` | | Machine password for LAPI login (required when enabled) |
| `RAN_BAN_ON` | `attack,scan` | Classes that produce a CrowdSec alert (subset of `probe,attack,scan`). `probe` stays in logs and metrics only unless listed. If `scan` is not listed, a scan-classified session is reported as its own class instead (attack if it did something, otherwise probe, which is then filtered) |
| `RAN_ALERT_COOLDOWN` | `1h` | At most one alert per IP and class per cooldown (`0s` = disabled) |
| `RAN_SHUN` | `off` | With `on`, new TCP connections from a source are closed at accept time for the alert cooldown after an alert was accepted for it (see [Quiet repeat offenders](/hardening#quiet-repeat-offenders)). Needs `RAN_CROWDSEC`. Ignored sources and `probe` sessions never shun; UDP is untouched |
| `RAN_REPEAT_AFTER` | `5` | Number of accepted alerts for a source and class after which `RAN_REPEAT_COOLDOWN` applies instead of `RAN_ALERT_COOLDOWN` (whole number, at least 1) |
| `RAN_REPEAT_COOLDOWN` | | Cooldown (and shun window) after `RAN_REPEAT_AFTER` alerts. Unset follows `RAN_ALERT_COOLDOWN`, so nothing changes until it is set; `12h` is recommended together with `RAN_SHUN=on`. Must be greater than zero when set |
| `RAN_PROBE_SUMMARY_WINDOW` | `60s` | Window of the aggregated probe summary log line (`0s` = one log line per probe session) |
| `RAN_CROWDSEC_BATCH_INTERVAL` | `10s` | Batch flush interval (`0s` = immediate, one POST per alert, no batching) |
| `RAN_CROWDSEC_BATCH_SIZE` | `50` | Max alerts per batch POST (a batch is also flushed early at about 512 KiB) |
| `RAN_CROWDSEC_MAX_TRACKED` | `20000` | Cap of each of the three in-memory maps separately: alert cooldown, scan tracker and probe summaries (see sizing below) |

`RAN_CROWDSEC_BAN_DURATION`, `RAN_CROWDSEC_DECISION_CACHE` and
`RAN_CROWDSEC_DEDUP_WINDOW` were removed in 0.4.0. They are ignored; rán logs a
one-time warning at startup if one is still set.


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


## Connecting rán to CrowdSec

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
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    user: "65532:65532"
    environment:
      RAN_TRAPS: ssh,http,ftp,smtp,vnc,rdp
      RAN_CROWDSEC: "on"
      RAN_CROWDSEC_URL: http://crowdsec:8080
      RAN_CROWDSEC_MACHINE_ID: ran-honeypot
      RAN_CROWDSEC_PASSWORD: ${CROWDSEC_PASSWORD}
      RAN_BAN_ON: attack,scan
    ports:
      - "2222:2222"
      - "8081:8081"
      - "21:21"
      - "25:25"
      - "5900:5900"
      - "3389:3389"
      - "127.0.0.1:9550:9550"
    volumes:
      - ran-data:/data
    tmpfs:
      - /tmp
volumes:
  ran-data:
```

The hostname in `RAN_CROWDSEC_URL` (`crowdsec` here) must resolve from the rán
container: run the LAPI as another service of the same compose file, or attach
both containers to one shared Docker network. The first LAPI login happens at
startup and a failure is fatal (see [Troubleshooting](/troubleshooting)). The
[config builder](/builder) writes the same hardening flags for you.

## Escalation with CrowdSec profiles

CrowdSec evaluates `profiles.yaml` only for alerts that carry no decisions,
which is exactly what rán sends. Select on the class with the **event** form
`Alert.Events[0].GetMeta("class")`: `Alert.GetMeta("class")` reads only
alert-level meta and matches nothing. Profiles run top to bottom and stop at the
first `on_success: break`, so the rán profiles must come before any generic one.

rán ships the profile that matches your binary, so there is nothing to copy by
hand. Print it and save it as `/etc/crowdsec/profiles.yaml` (or append it above
your own profiles):

```bash
docker run --rm ghcr.io/st0o0/ran crowdsec-profile > profiles.yaml.local
# or, with a local binary
ran crowdsec-profile > profiles.yaml.local
```

The subcommand needs no configuration and prints the file embedded in the
binary. The same file is included below, and the integration test mounts it
into a real CrowdSec, so the docs, the binary and CI cannot diverge.

<!--@include: ./crowdsec-profile.generated.md-->

The profiles, in order:

- `ran_scan` and `ran_attack` ban the class with the escalating duration.
- `ran_noban` catches every other `custom/ran-*` alert (for example `probe`,
  which only reaches the LAPI when `RAN_BAN_ON` lists it), creates no decision
  and stops evaluation. A later catch-all profile, such as the stock
  `default_ip_remediation` (`Alert.Remediation == true`) or your own
  `Remediation == true` policy, therefore never bans a probe. The shipped file
  has no such fallback on purpose: it is your own policy and would hide the
  effect of `ran_noban`. Keep it below the rán profiles.

`duration_expr` overrides the profile `duration` (the fallback). Decisions
accumulate: every ban alert adds a decision row and older rows stay until they
expire, so a bouncer enforces the ban while any row is active (the longest one
decides). The `scan` class uses the same formula as `attack`. If you want
scanners to stay out longer, give the `scan` profile a harder formula, for
example a larger base or a longer cap.

| Alert for the IP | Prior decisions | Ban |
|---|---|---|
| 1st | 0 | 1h |
| 2nd | 1 | 3h |
| 3rd | 2 | 9h |
| 4th | 3 | 27h |
| 5th | 4 | 81h |
| 6th and later | 5 or more | 168h (cap) |

At the cap each further alert adds a fresh 168h decision, so a persistent
source keeps its ban renewed instead of shortened.

Two expression pitfalls, both covered by the integration test through the
observed durations (`crowdsec -t` compiles the expression but does not catch
the formatting fallback):

- Use lowercase `min`. The capitalized `Min` does not compile and CrowdSec
  exits fatally with `unknown name Min`.
- Use a float cap and `%.0fh`. `min(168, 3 ^ n)` returns the int literal at the
  cap, and `%.0f` then fails silently and falls back to the base `duration`
  (1h). `%dh` falls back the same way because `3 ^ n` is a float.

> **Prerequisite:** `duration_expr` requires CrowdSec 1.4 or later.

**Tested version.** The profile and the escalation table are tested against the
CrowdSec version stated above the profile, by a CI workflow that starts that
image as LAPI only, pushes alerts through the real rán sink and reads the
decisions back (scan and attack bans, escalation and cap, no decision for
`probe`, no decision for an allowlisted IP). Renovate keeps the pinned image
current, so a CrowdSec release that changes profile semantics fails CI first.
Use the list key `filters:`; the singular `filter:` key is rejected and the LAPI
exits with `field filter not found in type csconfig.ProfileCfg`. A comment-only
YAML document after a `---` separator stops the profile list from loading
further profiles, so keep comments inside a profile document.

Verify with:

```bash
cscli alerts list -a
cscli decisions list -o json
```

`cscli alerts list` hides alerts without an active decision (probes,
allowlisted sources) unless you pass `-a`.

## What the ban protects

A CrowdSec decision is only as useful as the component that enforces it.

- A reverse proxy bouncer (Caddy, nginx, Traefik) only covers HTTP traffic
  behind it. The trap ports stay open to a banned source unless a firewall
  bouncer enforces the ban on the host, or `RAN_SHUN=on` closes the connections
  at accept time (see [Quiet repeat offenders](/hardening#quiet-repeat-offenders)).
- Persistent sources renew their ban: every alert after the cooldown adds a
  decision, and the escalation pins at the 168h cap. Use `RAN_REPEAT_AFTER` and
  `RAN_REPEAT_COOLDOWN` to slow the alert rate of sources that never leave.
- The overlap between trap sources and the sites behind a proxy was small in
  measurements, so the main value of the integration is detection and the
  community sharing of what the honeypot sees, not protecting your own sites.

## Reading the logs

Sessions of UDP traps (`dns`, `ntp`, `snmp`, `sip`) log a source address that
anyone can spoof: such lines never alert and must not be counted as attackers.
When you count or rank sources in your log stack, filter on `transport=tcp`
(the session log lines carry the `transport` attribute), for example in
LogQL `{app="ran"} | json | transport="tcp"`.

## Community sharing per class

What reaches CrowdSec is decided in rán's sink and by your CAPI settings:

| Class | Sent to the LAPI | Shared with the community |
|---|---|---|
| `scan` | yes (default `RAN_BAN_ON`) | yes, together with the bans your profile creates |
| `attack` | yes (default `RAN_BAN_ON`) | yes |
| `probe` | no, unless you list it in `RAN_BAN_ON` | not sent; if you list it, the alert is still shared even though `ran_noban` creates no decision |

Alerts are `simulated: false`, so CrowdSec forwards them to the Central API
when sharing is enabled; the profile decides bans only. Passwords never leave
the host (the sink drops password-like meta keys and `RAN_LOG_PASSWORDS` only
controls the logs). To keep everything local, disable CAPI sharing on the
CrowdSec side or leave `probe` out of `RAN_BAN_ON`.


## CrowdSec behaviors to know


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


## Migrating from 0.3.x


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

Behavior changes in the release after 0.4.0 (existing deployments):

- `mysql` and `postgres` now honor `RAN_MAX_AUTH_RETRIES` and accept up to 3
  attempts per session by default (they used to take one). Set
  `RAN_MYSQL_MAX_AUTH_RETRIES=1` and `RAN_POSTGRES_MAX_AUTH_RETRIES=1` to keep
  one attempt. A client that resends the same password ends the session and is
  counted once. `mysql` only asks again for clients that set `CLIENT_PLUGIN_AUTH`.
  `rdp` stays a single attempt.
- `modbus` read-only sessions (function codes 1 to 4 and 43) are now `probe`
  and no longer produce an alert under the default `RAN_BAN_ON=attack,scan`.
  Writes, function code 17 and unknown codes still count as `attack`.
- A source that touches 5 distinct destination ports within the scan window is
  now classified `scan`, in addition to the 3 distinct protocols rule.
- `ssh` auth attempts carry a `method` log attribute and alert meta key.
  `adb` auth attempts carry `method` plus `key_hash` (public key) or
  `signature_hash` (signature); `adb` now also records `shell:` and `exec:` opens.
- `telnet` listens on `:23` and `:2323` by default (set `RAN_TELNET_ADDR=:23` to
  keep one port) and strips IAC option bytes from the captured credentials.
- `http` requests for known exploit and recon paths or with a JNDI string are
  now commands and classify as `attack`.
- New traps `s7comm`, `enip`, `pjl` and `ipp` are available (see the trap
  table; add them to `RAN_TRAPS` to enable them). `ipp` is HTTP based.
- New traps `docker`, `kubernetes` and `mongodb` are available (see the trap
  table; add them to `RAN_TRAPS` to enable them).

Upgrading with `RAN_PROXY_PROTOCOL=on` (breaking): `RAN_PROXY_TRUSTED` is now
required and `ran check-config` fails without it. Set it to the address or CIDR
of your proxy or tunnel (for example `RAN_PROXY_TRUSTED=10.0.0.0/8`); peers
outside the list are closed before they can send a header. To keep the old
behavior for a while set `RAN_PROXY_TRUSTED=any`; this lets any host that can
reach the port forge the reported source address (and get an innocent IP
banned), and ran logs a warning at every start. With the protocol off nothing
changes.

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

Upgrading to the release with `RAN_FINGERPRINT` (banners change once): the
SSH, MySQL, HTTP/HTTPS, SMTP and Elasticsearch banners are now picked from
built-in sets with a seed that is generated on first start and kept in
`RAN_FINGERPRINT_SEED_PATH` (default `/data/fingerprint_seed`). After that
one-time change they stay stable across restarts. The `/data` volume must be
writable by uid `65532` (see the ownership note above) to persist the seed;
otherwise the seed is ephemeral and the banners change on every restart. Set
`RAN_FINGERPRINT=fixed` to keep the old banners if you parse them. New alert
meta key `kind` on `vnc`, `rdp`, `oracle`, `mqtt`, `modbus`, `minecraft` and
`adb` (see [Classification](/classification-and-alerts#classification)).

