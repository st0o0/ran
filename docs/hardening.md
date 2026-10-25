# Hardening

## Threat model

rán is a sensor, not a defense. It exposes deliberately weak fake services and
reports who touched them; it does not protect the host it runs on.

- **Spoofing resistance.** The alert identity is always the TCP peer address.
  Header values (`X-Forwarded-For`, `X-Real-IP`) are only logged as
  `claimed_client_ip`. UDP source addresses can be forged, so UDP traps never
  raise alerts; they only log and count metrics. Only TCP sessions with a
  publicly routable peer can produce a CrowdSec alert.
- **PROXY protocol trust.** With `RAN_PROXY_PROTOCOL=on` the address in the
  header is trusted as the peer, but only when the socket peer is listed in
  `RAN_PROXY_TRUSTED` (mandatory; checked before any header is read). Other peers
  are dropped and counted. `RAN_PROXY_TRUSTED=any` removes this protection: any
  host that can reach the port can then forge the address, so list your proxies
  and firewall the listener as well. A compromised or shared proxy in the list can
  still forge addresses. Behind docker-proxy, Kubernetes SNAT or any NAT or load
  balancer that rewrites the source, all clients appear from the gateway
  address; trusting that address trusts everyone who can reach the port.
- **TLS fingerprints are claims.** The `https` trap records SNI, JA3 and JA4 of
  the ClientHello as alert meta. They are client controlled (any client can
  send any SNI or mimic a fingerprint), so they are context for triage, never
  identity. The certificate is self-signed with `CN=localhost` and imitates no
  real host. The key is generated per instance and is not meant to be reused. To accept old scanners the trap deliberately weakens its TLS: minimum version TLS 1.0 and all cipher suites Go implements (no `GODEBUG` setting is needed, because an explicit `MinVersion` and `CipherSuites` override the defaults that `tls10server`, `tlsrsakex` and `tls3des` control). Negotiated sessions are therefore not confidential; the traffic is attacker traffic by definition.
- **Detectability.** Banners are generic and plausible, and
  [seeded banner profiles](/configuration#banner-profiles) make instances differ, but a
  determined attacker can fingerprint any honeypot (protocol behavior, timing,
  the shared Go TLS and SSH stacks, closed or fake services). This does not
  defeat fingerprinting. Do not rely on rán staying hidden.
- **Isolation.** Run it unprivileged, without capabilities and with a read-only
  filesystem (see below). Never place it on a network segment with sensitive
  hosts.

### Recommended container settings


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


## Behind a reverse proxy

A host often mixes traps that face the internet directly (`ssh`, `vnc`, `rdp`, ...)
with one trap that sits behind a reverse proxy (usually `http` or `https`).
`RAN_PROXY_PROTOCOL` takes a list of trap names for this case, so only the
proxied traps require a PROXY header:

```bash
RAN_TRAPS=ssh,vnc,http
RAN_PROXY_PROTOCOL=http
RAN_PROXY_TRUSTED=10.0.0.0/8
```

Here `ssh` and `vnc` accept direct connections as before, while `http` accepts
only connections from the listed proxy peers and takes the client address from
the PROXY header. Connections from any other peer to `http` are dropped before the
header is read. `RAN_PROXY_PROTOCOL=on` still means every TCP trap; `off` or an
empty value means none. Names are case-insensitive and may be separated by
spaces. UDP traps and unknown names fail startup; a name that is not in
`RAN_TRAPS` only logs a warning. `RAN_PROXY_TRUSTED` is mandatory as soon as one
trap uses PROXY protocol and is shared by all of them, so keep it narrow. The
startup log and `ran check-config` print the traps that expect a PROXY header and
the trusted peers; check them after every change, because a typo in the list
would otherwise leave a trap without PROXY protocol.

**Caddy.** Tell Caddy to send a PROXY v2 header in the upstream transport of the
honeypot route:

```caddyfile
honeypot.example.com {
	reverse_proxy ran:8081 {
		transport http {
			proxy_protocol v2
		}
	}
}
```

Use the address of the `http` trap as the upstream and put the address Caddy
connects from in `RAN_PROXY_TRUSTED`.

**Shared network namespace.** When the proxy and ran share one network namespace
(for example containers in one pod, or `network_mode: service:...`), ran sees the
proxy as loopback. Trust both loopback addresses:

```bash
RAN_PROXY_TRUSTED=127.0.0.1,::1
```

Headers such as `X-Forwarded-For` and `X-Real-IP` stay log-only
(`claimed_client_ip`); the alert source is the address from the PROXY header, and
only a trusted peer can set it. A trap is either proxied or direct: a proxied
trap must not also be published directly, because direct connections to it are
dropped. If you need both, publish the trap on its proxied port only.


## Quiet repeat offenders

On a host whose trap ports are open to the internet, a banned source often keeps
hammering the traps: a ban enforced only by a reverse proxy bouncer does not stop
traffic to the trap ports. A handful of sources can then produce most of the log
volume (one brute-force bot made tens of thousands of login attempts in a few
hours) and keep renewing their own ban with every new alert. Two opt-in settings
reduce that. The defaults reproduce the previous behavior.

```bash
RAN_CROWDSEC=on
RAN_SHUN=on
RAN_REPEAT_COOLDOWN=12h
```

**Shun (`RAN_SHUN`).** After ran accepted an alert for a source (class `attack`
or `scan`, passed the validity, ignore and cooldown checks, and was queued), new
TCP connections from that source are closed at accept time until the cooldown
that applied to that alert has passed. There is no session, no goroutine, no
banner and no per-connection log line, so the source sees what a firewalled host
looks like. The check runs after PROXY protocol handling (the resolved source
address) and before the session limiter, and it covers every TCP trap including
the HTTP based ones; it applies to the source address regardless of class or
protocol. `RAN_IGNORE_IPS` sources are never shunned, `probe` activity never
starts a shun, and UDP traps are untouched. When the window ends, the next attack
is served and alerts again, so the CrowdSec escalation ladder advances as
designed.

**Repeat cooldown (`RAN_REPEAT_AFTER`, `RAN_REPEAT_COOLDOWN`).** After
`RAN_REPEAT_AFTER` accepted alerts (default 5, the length of the documented
ladder) for a source and class, the cooldown and with it the shun window become
`RAN_REPEAT_COOLDOWN`. Unset, it equals `RAN_ALERT_COOLDOWN` and nothing changes;
`12h` is the recommended value. Because the longest ban step (168h) is far longer
than the repeat cooldown, the ban never lapses between alerts. The counter is
forgotten after about seven days of silence.

**What you see.** Suppressed connections are counted in
`ran_connections_rejected_total{reason="shun"}`, the number of sources inside a
window in `ran_shun_active_sources`, and when a window ends (or the entry is
evicted, or ran shuts down) ran writes one `shun summary` log line per source and
window with `source_ip`, `count`, `protocols` (at most 8) and `window_seconds`.
The table behind this is bounded by `RAN_CROWDSEC_MAX_TRACKED` with oldest-first
eviction (`ran_tracked_entries{map="offender"}`); eviction loses a shun, never
causes a ban.

**Limits.** Shun and the repeat counters key on the exact source address. An IPv6
source that rotates addresses inside one /64 is not grouped: each address gets its
own counter and its own window. When the offender table is full, the oldest entry
is dropped even if its shun window is still active, and that source is served
again (watch `ran_tracked_evictions_total{map="offender"}` and raise
`RAN_CROWDSEC_MAX_TRACKED` if it rises).

**Relation to firewall bouncers.** A firewall bouncer (nftables or iptables)
enforces a CrowdSec decision before the traffic reaches ran and remains the
better tool when you can run one. Shun is the same loop enforced inside ran, for
hosts where the bouncer acts elsewhere (for example only at a reverse proxy). It
uses ran's own alerts and does not query CrowdSec decisions, so it does not know
about bans made for other reasons.

**Trade-off.** A shunned source produces no more sessions, credential samples or
alerts during its window; only the connection that caused the alert is observed.
Operators who collect research data should leave `RAN_SHUN` off. The cooldown
deliberately renews bans: with `RAN_REPEAT_COOLDOWN=12h` a persistent source
alerts about twice a day, which keeps its ban alive. A repeat cooldown longer than the
longest ban step lets the ban lapse between alerts. A forged
PROXY header (`RAN_PROXY_TRUSTED=any`) can make ran shun an arbitrary address,
another reason to keep that list narrow.
