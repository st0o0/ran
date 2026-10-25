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
