# Classification and alerts

## Classification


| Class | Meaning |
|---|---|
| `probe` | Connect and banner only: no auth attempt, command or payload byte |
| `attack` | At least one auth attempt, command or payload byte |
| `scan` | The same source IP touched at least 3 distinct TCP trap protocols or at least 5 distinct destination ports within about 10 minutes |

Scan detection never counts UDP (spoofable), sources in `RAN_IGNORE_IPS` or non-public source addresses, and
its in-memory map is capped, with at most 16 ports remembered per source (oldest entries are evicted first, which only delays
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
`function_code`, `player_name`). Single-request traps also add a fixed `kind` key
that says what was seen (a closed vocabulary per trap, never client data), so
CrowdSec profiles can tell them apart with `Alert.Events[0].GetMeta("kind")`:
`vnc` `auth_response`; `rdp` `connection_request`; `oracle` and `mqtt` `connect`;
`modbus` `write` or `unknown_function`; `minecraft` `status`, `login` or
`handshake`; `adb` `connect`, `auth` or `shell_command`; `s7comm` `write`,
`control` or `unknown`; `enip` `send_data` or `unknown`; `pjl` `fs_command`,
`set`, `other` or `print_data`; `ipp` `print_job` or `other`. The same field
appears in the log lines of probe requests with the probe vocabulary (`s7comm`
`connect`, `setup`, `identify`; `enip` `list_identity`, `list_services`,
`list_interfaces`, `register_session`, `unregister_session`, `nop`; `pjl` `info`,
`job`; `ipp` `attributes`). The new ICS and printer traps use fixed, static
identities (no seeded variation). The meta is bounded:

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
plain GET requests without a body, HTTP `GET`/`HEAD` requests that match no exploit path or JNDI string, Minecraft server-list pings, Modbus read requests (function codes 1 to 4) and device identification (43), S7comm setup and SZL reads, EtherNet/IP identity and session commands, PJL information queries and IPP `Get-Printer-Attributes`, `Get-Jobs` and `Validate-Job`. An ADB CNXN still counts as payload.


## Logging of probes


TCP probe sessions are not logged one by one. Per source IP and
`RAN_PROBE_SUMMARY_WINDOW` rán writes one summary line
(`action: probe_summary`, `sessions`, `protocols`). Attack and scan sessions keep
their full per-event lines (credentials, commands, payloads). A probe session that
triggers a scan alert is still summarized in the logs. UDP sessions are never
summarized: they always log `connect` and `disconnect` lines. The `ran_*`
metrics are still updated per session, so dashboards are unaffected.
Sessions from `RAN_IGNORE_IPS` sources are excluded from the summary and keep their
per-session lines, marked `ignored=true`.


## Alert pipeline


```
trap session ──▶ Classify (probe / attack / scan) ──▶ Alert pipeline ──▶ POST /v1/alerts
                                                       │
   IP validation ─▶ class filter (RAN_BAN_ON) ─▶ cooldown ─▶ batch queue
        invalid          filtered                  cooldown       queued / dropped
```

Sources in `RAN_IGNORE_IPS` never enter the pipeline: the sensor drops them
before classification, so there is no pipeline stage for them. Use
`ran_ignored_sessions_total` to see how many sessions were ignored.

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

<a id="proxy-protocol-trust"></a>
With `RAN_PROXY_PROTOCOL`, the PROXY v1 or v2 header is required, and only peers
listed in `RAN_PROXY_TRUSTED` may send one. The check uses the socket peer
address of the accepted connection (IPv4-mapped IPv6 peers match their IPv4
entry), never header content, and happens before a header is read: a connection
from any other peer is closed at once, counted in
`ran_proxy_protocol_dropped_total`, and produces no session, no alert and no log
line with a claimed address (only a debug line without addresses). The variable
is mandatory with the protocol on; `RAN_PROXY_TRUSTED=any` trusts every peer and
logs a warning at startup. Prefixes shorter than /8 (such as `0.0.0.0/0` or `::/0`) are
accepted with a warning; the threshold is /8 for both address families, so an
IPv6 `/16` or an IPv4 `/9` does not warn. A connection from a trusted peer must send a valid header within 3 seconds; a connection that sends other bytes,
closes early or stays silent is closed and counted in
`ran_proxy_protocol_dropped_total`, never handled as a plain connection. A
silent peer does not block other clients. At most 1024 connections per listen
address may be waiting for a header (or for the trap to take them) at once;
further ones are closed immediately and counted too. The mode applies to all TCP
traps and never to UDP. `PROXY ... UNKNOWN` (v1) and `LOCAL` (v2) headers keep
the address of the proxy itself. The list is read once at startup and applies
to every listener of every TCP trap. Keep it as narrow as possible and still
firewall the listener where you can: a peer inside a trusted range can forge
headers, and with `any` a header lets any peer that can connect directly choose
the source address ran reports, so any public IP can be reported and then banned.

**Warning: NAT, docker-proxy and load balancers.** Behind docker-proxy,
Kubernetes SNAT (for example `externalTrafficPolicy: Cluster`) or any NAT or
load balancer that rewrites the source address, every client reaches ran from
the gateway address. Adding that address to `RAN_PROXY_TRUSTED` then trusts every
client who can reach the port and re-opens header forging, exactly as `any`
does. List only the real proxy or tunnel peer address as ran sees it, and prefer
a listener that is isolated by a firewall so that only the proxy can connect.

