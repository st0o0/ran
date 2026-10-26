import type { BuilderState, Hint, Register, ScenarioId } from './types'
import { cloneState, effectiveEnv, setTrap, setValue } from './state'
import { trapAddrs } from './addrs'

export interface Scenario {
  id: ScenarioId
  label: string
  summary: string
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'direct',
    label: 'Direct',
    summary: 'Traps face the network directly. No PROXY protocol, no CrowdSec.'
  },
  {
    id: 'reverse-proxy',
    label: 'Behind a reverse proxy',
    summary: 'Chosen web traps sit behind a proxy that sends a PROXY header; all other traps stay direct.'
  },
  {
    id: 'shared-namespace',
    label: 'Shared network namespace',
    summary: 'The proxy runs in the same network namespace, so ran sees it as loopback.'
  },
  {
    id: 'crowdsec',
    label: 'With CrowdSec',
    summary: 'Report alerts to a CrowdSec local API whose profiles decide the bans.'
  }
]

export const PROXY_PRESET_TRUSTED = '172.16.0.0/12'
export const LOOPBACK_TRUSTED = '127.0.0.1,::1'
export const CROWDSEC_PRESET = {
  RAN_CROWDSEC: 'on',
  RAN_CROWDSEC_URL: 'http://crowdsec:8080',
  RAN_CROWDSEC_MACHINE_ID: 'ran-honeypot'
}

const PRESET_TRUSTED = [PROXY_PRESET_TRUSTED, LOOPBACK_TRUSTED]
const WEB_TRAPS = ['http', 'https']

/** A scenario only sets values; everything can be changed afterwards. */
export function applyScenario(reg: Register, state: BuilderState, id: ScenarioId): BuilderState {
  let next = cloneState(state)
  next.scenario = id
  if (id === 'direct') {
    next.proxied = []
    if (PRESET_TRUSTED.includes(next.values.RAN_PROXY_TRUSTED ?? '')) {
      next = setValue(reg, next, 'RAN_PROXY_TRUSTED', '')
    }
    return next
  }
  if (id === 'crowdsec') {
    next.proxied = []
    for (const [k, v] of Object.entries(CROWDSEC_PRESET)) {
      if (!next.values[k]) next = setValue(reg, next, k, v)
    }
    return next
  }
  // reverse-proxy and shared-namespace
  if (!next.traps.some((t) => WEB_TRAPS.includes(t))) next = setTrap(next, 'http', true)
  next.proxied = next.traps.filter((t) => WEB_TRAPS.includes(t))
  if (id === 'shared-namespace') {
    next = setValue(reg, next, 'RAN_PROXY_TRUSTED', LOOPBACK_TRUSTED)
  } else if (!next.values.RAN_PROXY_TRUSTED || next.values.RAN_PROXY_TRUSTED === LOOPBACK_TRUSTED) {
    next = setValue(reg, next, 'RAN_PROXY_TRUSTED', PROXY_PRESET_TRUSTED)
  }
  return next
}

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

/** Scenario specific advice shown next to the output. */
export function scenarioHints(reg: Register, state: BuilderState): Hint[] {
  const out: Hint[] = []
  const env = effectiveEnv(state)
  if (state.scenario === 'reverse-proxy' || state.scenario === 'shared-namespace') {
    if (state.proxied.length === 0) {
      out.push({
        id: 'proxy-pick-trap',
        message: 'Choose at least one trap that sits behind the proxy; without one, PROXY protocol stays off.'
      })
    }
    for (const trap of state.proxied) {
      const addr = trapAddrs(reg, env, trap)[0]
      if (!addr) continue
      const host = state.scenario === 'shared-namespace' ? '127.0.0.1' : 'ran'
      out.push({
        id: `caddy-${trap}`,
        message: `Caddy: send a PROXY v2 header to the ${trap} trap. A proxied trap must not also be published directly, because direct connections to it are dropped.`,
        code: caddySnippet(`${host}:${addr.port}`)
      })
    }
    if (state.scenario === 'reverse-proxy') {
      out.push({
        id: 'trusted-narrow',
        message: `RAN_PROXY_TRUSTED defaults to ${PROXY_PRESET_TRUSTED} (the default Docker bridge range). Narrow it to the address the proxy connects from.`
      })
    } else {
      out.push({
        id: 'trusted-loopback',
        message: 'Proxy and ran share one network namespace (for example containers in one pod, or network_mode: service:...), so ran sees the proxy as loopback: RAN_PROXY_TRUSTED=127.0.0.1,::1. Do not publish the proxied trap port to the host.'
      })
    }
  }
  if (state.scenario === 'crowdsec') {
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
