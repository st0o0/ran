import type { BuilderState, Hint, Register } from './types'
import { crowdsecOn, effectiveEnv, findTrap, isTruthy } from './state'
import { trapAddrs } from './addrs'

export const WIDE_PORT_SET = 20
export const LOOPBACK_TRUSTED = '127.0.0.1,::1'

/** Caddyfile for one proxied trap; the example host name is reserved for documentation. */
export function caddySnippet(upstream: string): string {
  return [
    'honeypot.example.com {',
    `\treverse_proxy ${upstream} {`,
    '\t\ttransport http {',
    '\t\t\tproxy_protocol v2',
    '\t\t}',
    '\t}',
    '}'
  ].join('\n')
}

/** Advice that is not an error or warning. The checks themselves come from the Go code (checker.ts). */
export function hints(reg: Register, state: BuilderState): Hint[] {
  const env = effectiveEnv(state)
  const out: Hint[] = []
  const udp = state.traps.filter((t) => findTrap(reg, t)?.transport === 'UDP')
  if (udp.length > 0) {
    out.push({
      id: 'udp-log-only',
      message: `${udp.join(', ')} (UDP) log and count only and never alert, because UDP source addresses can be spoofed. Expect more log lines than alerts; RAN_UDP_RATE_* limit the volume.`
    })
  }
  let ports = 0
  for (const t of state.traps) ports += trapAddrs(reg, env, t).length
  if (ports >= WIDE_PORT_SET) {
    out.push({
      id: 'wide-port-set',
      message: `${ports} listen ports are configured. A wide port set raises log volume and the number of exposed ports; consider RAN_PROBE_SUMMARY_WINDOW and RAN_MAX_SESSIONS.`
    })
  }
  if (state.traps.includes('catchall') || state.traps.includes('banner')) {
    out.push({
      id: 'catchall-volume',
      message: 'catchall and banner listen on operator-chosen ports and see unfiltered scan traffic; keep the port set small and watch the log volume.'
    })
  }
  if ((env.RAN_PROXY_TRUSTED ?? '').trim() === 'any') {
    out.push({
      id: 'trusted-any',
      message: 'RAN_PROXY_TRUSTED=any lets every peer send a PROXY header and so spoof the client address. Use a narrow list plus a firewall.'
    })
  }

  // Proxy hints
  if (state.proxied.length > 0) {
    const shared = (env.RAN_PROXY_TRUSTED ?? '') === LOOPBACK_TRUSTED
    for (const trap of state.proxied) {
      const addr = trapAddrs(reg, env, trap)[0]
      if (!addr) continue
      const host = shared ? '127.0.0.1' : 'ran'
      out.push({
        id: `caddy-${trap}`,
        message: `Caddy: send a PROXY v2 header to the ${trap} trap. A proxied trap must not also be published directly, because direct connections to it are dropped.`,
        code: caddySnippet(`${host}:${addr.port}`)
      })
    }
    if (shared) {
      out.push({
        id: 'trusted-loopback',
        message: 'Proxy and ran share one network namespace (for example containers in one pod, or network_mode: service:...), so ran sees the proxy as loopback: RAN_PROXY_TRUSTED=127.0.0.1,::1. Do not publish the proxied trap port to the host.'
      })
    } else {
      out.push({
        id: 'trusted-narrow',
        message: `Narrow RAN_PROXY_TRUSTED to the address the proxy connects from.`
      })
    }
  }

  // CrowdSec hints
  if (crowdsecOn(reg, env)) {
    out.push({
      id: 'crowdsec-password',
      message: 'The export contains RAN_CROWDSEC_PASSWORD=CHANGE_ME. Register the machine with "cscli machines add" and put the real password in only at deployment time, never into a shared file.'
    })
    out.push({
      id: 'crowdsec-url',
      message: 'Set RAN_CROWDSEC_URL to the address of your local API; http://crowdsec:8080 assumes both containers share a Docker network.'
    })
    out.push({
      id: 'crowdsec-profile',
      message: 'rán does not ban by itself: CrowdSec needs a profile. Print the one that matches your binary with "ran crowdsec-profile" (for example: docker run --rm ghcr.io/st0o0/ran crowdsec-profile > profiles.yaml.local) and install it as /etc/crowdsec/profiles.yaml before any generic profile.'
    })
    out.push({
      id: 'crowdsec-shun',
      message: 'Optional: RAN_SHUN=on closes new TCP connections from a source while its alert cooldown runs, so trap ports honor the ban without a firewall bouncer (see Quiet repeat offenders in the hardening guide). It is off by default.'
    })
  }

  return out
}
