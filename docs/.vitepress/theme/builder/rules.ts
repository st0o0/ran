import {
  type BuilderCase,
  type BuilderState,
  type Hint,
  type Issue,
  type Register
} from './types'
import { crowdsecOn, effectiveEnv, envGet, findTrap, isTruthy, resolveSetting, splitList } from './state'

export interface ParsedAddr {
  host: string
  port: number
}

/** Parses "host:port" entries, comma separated. Invalid entries are returned in `bad`. */
export function parseAddrList(raw: string): { addrs: ParsedAddr[]; bad: string[] } {
  const addrs: ParsedAddr[] = []
  const bad: string[] = []
  for (const part of raw.split(',').map((p) => p.trim()).filter((p) => p !== '')) {
    const i = part.lastIndexOf(':')
    const portText = i < 0 ? '' : part.slice(i + 1)
    const port = Number(portText)
    if (i < 0 || !/^\d+$/.test(portText) || port < 1 || port > 65535) {
      bad.push(part)
      continue
    }
    addrs.push({ host: part.slice(0, i).replace(/^\[|\]$/g, ''), port })
  }
  return { addrs, bad }
}

/** Listen addresses of one trap: the override or the register default. */
export function trapAddrs(reg: Register, env: Record<string, string>, trap: string): ParsedAddr[] {
  const def = findTrap(reg, trap)
  if (!def) return []
  if (def.addressless) {
    const raw = env[def.addr_var] ?? ''
    if (def.name === 'banner') {
      // port=name:banner pairs
      const out: ParsedAddr[] = []
      for (const pair of raw.split(',')) {
        const m = /^\s*(\d+)\s*=/.exec(pair)
        if (m) out.push({ host: '', port: Number(m[1]) })
      }
      return out
    }
    return parseAddrList(raw).addrs
  }
  return parseAddrList(env[def.addr_var] ?? def.default_addr).addrs
}

const DURATION = /^(\d+(\.\d+)?(ns|us|ms|s|m|h))+$/

function checkValues(reg: Register, env: Record<string, string>, out: Issue[]): void {
  for (const [key, value] of Object.entries(env)) {
    const hit = resolveSetting(reg, key)
    if (!hit) continue
    const { def } = hit
    const v = value.trim()
    if (v === '') continue
    if (def.kind === 'int' && !/^\d+$/.test(v)) {
      out.push({ id: `bad-int-${key}`, level: 'error', message: `${key} must be a whole number >= 0, got "${v}".` })
    } else if (def.kind === 'duration' && v !== '0' && !DURATION.test(v)) {
      out.push({ id: `bad-duration-${key}`, level: 'error', message: `${key} must be a duration such as 30s or 1h, got "${v}".` })
    } else if (def.kind === 'enum' && def.enum && !def.enum.includes(v.toLowerCase())) {
      out.push({ id: `bad-enum-${key}`, level: 'error', message: `${key} must be one of ${def.enum.join(', ')}, got "${v}".` })
    } else if (def.kind === 'addr') {
      const { bad } = parseAddrList(v)
      for (const b of bad) {
        out.push({ id: `bad-addr-${key}`, level: 'error', message: `${key} has an invalid listen address "${b}"; use host:port or :port with a port from 1 to 65535.` })
      }
    }
  }
}

/** Evaluates a flat environment (variables that differ from the default). */
export function evaluateEnv(reg: Register, env: Record<string, string>): Issue[] {
  const out: Issue[] = []
  const get = (k: string) => envGet(reg, env, k)

  const traps = splitList(env.RAN_TRAPS ?? '').map((t) => t.toLowerCase())
  if (traps.length === 0) {
    out.push({ id: 'no-trap', level: 'error', message: 'at least one trap must be enabled; set RAN_TRAPS.' })
  }
  for (const t of traps) {
    if (!findTrap(reg, t)) {
      out.push({ id: `unknown-trap-${t}`, level: 'error', message: `unknown trap "${t}" in RAN_TRAPS.` })
    }
  }

  // PROXY protocol
  const proxyRaw = get('RAN_PROXY_PROTOCOL').trim().toLowerCase()
  const proxyAll = proxyRaw === 'on'
  const proxyList = proxyAll || !isTruthy(proxyRaw) ? [] : splitList(proxyRaw)
  const proxyActive = proxyAll || proxyList.length > 0
  for (const name of proxyList) {
    const trap = findTrap(reg, name)
    if (!trap) {
      out.push({ id: `proxy-unknown-${name}`, level: 'error', message: `unknown trap "${name}" in RAN_PROXY_PROTOCOL.` })
    } else if (trap.transport === 'UDP') {
      out.push({ id: `proxy-udp-${name}`, level: 'error', message: `${name} is a UDP trap and cannot use PROXY protocol; remove it from RAN_PROXY_PROTOCOL.` })
    } else if (!traps.includes(name)) {
      out.push({ id: `proxy-not-enabled-${name}`, level: 'warning', message: `${name} is listed in RAN_PROXY_PROTOCOL but is not enabled in RAN_TRAPS, so the entry has no effect.` })
    }
  }
  const trusted = get('RAN_PROXY_TRUSTED').trim()
  if (proxyActive && trusted === '') {
    out.push({ id: 'proxy-no-trusted', level: 'error', message: 'RAN_PROXY_TRUSTED is required when PROXY protocol is used; list the proxy addresses or ranges.' })
  }
  if (!proxyActive && trusted !== '') {
    out.push({ id: 'trusted-without-proxy', level: 'warning', message: 'RAN_PROXY_TRUSTED is set but no trap uses PROXY protocol, so it has no effect.' })
  }

  // UDP rate
  const burst = Number(get('RAN_UDP_RATE_BURST'))
  const rate = Number(get('RAN_UDP_RATE_PER_SOURCE'))
  if (Number.isFinite(burst) && Number.isFinite(rate) && burst < rate) {
    out.push({ id: 'udp-burst-below-rate', level: 'error', message: `RAN_UDP_RATE_BURST (${burst}) must not be smaller than RAN_UDP_RATE_PER_SOURCE (${rate}).` })
  }

  // Addressless traps need their address variable
  for (const name of traps) {
    const trap = findTrap(reg, name)
    if (trap?.addressless && (env[trap.addr_var] ?? '').trim() === '') {
      out.push({ id: `addr-required-${name}`, level: 'error', message: `${trap.addr_var} is required when ${name} is enabled in RAN_TRAPS.` })
    }
  }

  // CrowdSec
  if (crowdsecOn(reg, env)) {
    if (get('RAN_CROWDSEC_URL').trim() === '') {
      out.push({ id: 'crowdsec-no-url', level: 'error', message: 'RAN_CROWDSEC_URL is required when RAN_CROWDSEC is on.' })
    }
    if (get('RAN_CROWDSEC_MACHINE_ID').trim() === '') {
      out.push({ id: 'crowdsec-no-machine', level: 'error', message: 'RAN_CROWDSEC_MACHINE_ID is required when RAN_CROWDSEC is on.' })
    }
  }

  checkValues(reg, env, out)

  // Port conflicts (same transport, same listen address)
  const seen = new Map<string, string>()
  for (const name of traps) {
    const trap = findTrap(reg, name)
    if (!trap) continue
    for (const a of trapAddrs(reg, env, name)) {
      const key = `${trap.transport}/${a.host}:${a.port}`
      const prev = seen.get(key)
      if (prev && prev !== name) {
        out.push({ id: `port-conflict-${a.port}`, level: 'error', message: `${prev} and ${name} both listen on ${trap.transport} port ${a.port}; give one of them another address.` })
      } else {
        seen.set(key, name)
      }
    }
  }
  return out
}

export function evaluate(reg: Register, state: BuilderState): Issue[] {
  return evaluateEnv(reg, effectiveEnv(state))
}

export type Outcome = 'ok' | 'warning' | 'error'

export function outcomeOf(issues: Issue[]): Outcome {
  if (issues.some((i) => i.level === 'error')) return 'error'
  if (issues.some((i) => i.level === 'warning')) return 'warning'
  return 'ok'
}

/** Replays one shared case vector; returns a failure description or null. */
export function checkCase(reg: Register, c: BuilderCase): string | null {
  const issues = evaluateEnv(reg, c.env)
  const outcome = outcomeOf(issues)
  if (outcome !== c.expect) {
    return `${c.id}: expected ${c.expect}, got ${outcome} (${issues.map((i) => i.message).join(' | ')})`
  }
  if (c.message_contains) {
    const needle = c.message_contains
    const hit = issues.some((i) => i.level === c.expect && i.message.includes(needle))
    if (!hit) return `${c.id}: no ${c.expect} message contains "${needle}"`
  }
  return null
}

export const WIDE_PORT_SET = 20

/** Advice that is not an error or warning (so it never changes a case outcome). */
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
  if (splitList(env.RAN_PROXY_TRUSTED ?? '').some((x) => x.toLowerCase() === 'any')) {
    out.push({
      id: 'trusted-any',
      message: 'RAN_PROXY_TRUSTED=any lets every peer send a PROXY header and so spoof the client address. Use a narrow list plus a firewall.'
    })
  }
  return out
}
