import {
  type BuilderCase,
  type BuilderState,
  type Hint,
  type Issue,
  type Register
} from './types'
import { crowdsecOn, effectiveEnv, envGet, findTrap, isTruthy, resolveSetting, splitList } from './state'
import { MAX_IGNORE_ENTRIES, parseIgnoreList } from './netaddr'

/** Spellings of the Go boolean reader (envReader.boolean), compared case-insensitively. */
export const BOOL_ON = ['on', 'true', 'yes', '1']
export const BOOL_OFF = ['off', 'false', 'no', '0']
export const CLASSES = ['probe', 'attack', 'scan']
/** config.MaxCooldown: upper bound of RAN_ALERT_COOLDOWN and RAN_REPEAT_COOLDOWN. */
export const MAX_COOLDOWN = '8760h'
const MAX_COOLDOWN_NS = BigInt(8760) * BigInt(3600) * BigInt(1000000000)
const INT64_MAX = BigInt('9223372036854775807')
const INT64_MIN = BigInt('-9223372036854775808')

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

/**
 * Duration syntax, aligned with Go's time.ParseDuration for the forms an operator
 * would write: an optional "+", one or more number+unit pairs (ns, us, the micro
 * sign or Greek mu followed by s, ms, s, m, h; fractions such as 1.5h are fine)
 * or a bare 0. Negative values are rejected on purpose: every duration variable
 * rejects them. Go also accepts "-0", which is exotic and not matched here.
 */
const MICRO = String.fromCharCode(0xb5) // micro sign
const MU = String.fromCharCode(0x3bc) // Greek small letter mu
const UNIT = `(?:ns|us|${MICRO}s|${MU}s|ms|s|m|h)`
const NUM = String.raw`(?:\d+\.?\d*|\.\d+)`
const DURATION = new RegExp(String.raw`^\+?(?:${NUM}${UNIT})+$`)
const DURATION_PART = new RegExp(`(${NUM})(${UNIT})`, 'g')

const UNIT_MS: Record<string, number> = { ns: 1e-6, us: 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 }
UNIT_MS[`${MICRO}s`] = 1e-3
UNIT_MS[`${MU}s`] = 1e-3

/** Milliseconds of a valid duration (see DURATION), or null when it is not valid. */
export function durationMs(raw: string): number | null {
  const v = raw.trim()
  if (/^\+?0$/.test(v)) return 0
  if (!DURATION.test(v)) return null
  let total = 0
  for (const m of v.matchAll(DURATION_PART)) total += Number(m[1]) * UNIT_MS[m[2]]
  return total
}

const UNIT_NS: Record<string, bigint> = {
  ns: BigInt(1),
  us: BigInt(1000),
  ms: BigInt(1000000),
  s: BigInt(1000000000),
  m: BigInt(60000000000),
  h: BigInt(3600000000000)
}
UNIT_NS[`${MICRO}s`] = BigInt(1000)
UNIT_NS[`${MU}s`] = BigInt(1000)

/** Exact nanoseconds of a valid duration (fractions truncated), or null when it is not valid. */
export function durationNs(raw: string): bigint | null {
  const v = raw.trim()
  if (/^\+?0$/.test(v)) return BigInt(0)
  if (!DURATION.test(v)) return null
  let total = BigInt(0)
  for (const m of v.matchAll(DURATION_PART)) {
    const [whole, frac = ''] = m[1].split('.')
    const unit = UNIT_NS[m[2]]
    total += BigInt(whole || '0') * unit
    if (frac !== '') total += (BigInt(frac) * unit) / BigInt(10) ** BigInt(frac.length)
  }
  return total
}

/** Durations that Load requires to be greater than zero (durationPositive). */
function mustBePositive(def: { name: string; family?: string }): boolean {
  return def.name === 'RAN_SESSION_TIMEOUT' || def.name === 'RAN_REPEAT_COOLDOWN' || def.family === 'SESSION_TIMEOUT'
}

function hasCooldownCap(def: { name: string }): boolean {
  return def.name === 'RAN_ALERT_COOLDOWN' || def.name === 'RAN_REPEAT_COOLDOWN'
}

const IGNORE_HELP = 'use IP addresses or CIDR ranges such as 8.8.8.8,1.1.1.0/24,2606:4700:4700::/48'

/** RAN_IGNORE_IPS and RAN_PROXY_TRUSTED (the latter also takes a lone "any"). */
function checkPrefixList(key: string, raw: string, out: Issue[]): void {
  if (key === 'RAN_PROXY_TRUSTED' && raw.trim() === 'any') return
  const r = parseIgnoreList(raw)
  if ('count' in r) return
  const tail = key === 'RAN_PROXY_TRUSTED' ? ` (or the single value "any" to trust every peer)` : ''
  const message = r.bad === undefined
    ? `${key} has more than ${MAX_IGNORE_ENTRIES} distinct entries; shorten the list or use wider CIDR ranges${tail}.`
    : `${key} has an invalid entry "${r.bad}" (${r.error}); ${IGNORE_HELP}${tail}.`
  out.push({ id: `bad-list-${key}`, level: 'error', message })
}

/** RAN_BAN_ON: a non-empty list of known classes, comma separated like Go. */
function checkClasses(key: string, raw: string, out: Issue[]): void {
  let n = 0
  for (const part of raw.split(',')) {
    const c = part.trim().toLowerCase()
    if (c === '') continue
    if (!CLASSES.includes(c)) {
      out.push({ id: `bad-class-${key}`, level: 'error', message: `${key} contains invalid class "${c}" (valid: probe, attack, scan); use a comma-separated list such as attack,scan.` })
      return
    }
    n++
  }
  if (n === 0) {
    out.push({ id: `bad-class-${key}`, level: 'error', message: `${key} must list at least one of probe, attack, scan, got "${raw.trim()}"; use a comma-separated list such as attack,scan.` })
  }
}

function checkValues(reg: Register, env: Record<string, string>, out: Issue[]): void {
  for (const [key, value] of Object.entries(env)) {
    const hit = resolveSetting(reg, key)
    if (!hit) continue
    const { def } = hit
    const v = value.trim()
    if (v === '') continue
    if (key === 'RAN_IGNORE_IPS' || key === 'RAN_PROXY_TRUSTED') {
      checkPrefixList(key, v, out)
    } else if (key === 'RAN_BAN_ON') {
      checkClasses(key, v, out)
    } else if (def.kind === 'bool') {
      const l = v.toLowerCase()
      if (!BOOL_ON.includes(l) && !BOOL_OFF.includes(l)) {
        out.push({ id: `bad-bool-${key}`, level: 'error', message: `${key} must be on or off, got "${v}"; use on, off, true, false, yes, no, 1 or 0.` })
      }
    } else if (def.kind === 'int') {
      const min = def.min ?? 0
      const bad = (message: string) => out.push({ id: `bad-int-${key}`, level: 'error', message })
      if (!/^[+-]?\d+$/.test(v)) {
        bad(`${key} must be a whole number >= ${min}, got "${v}".`)
      } else {
        const n = BigInt(v)
        if (n < INT64_MIN || n > INT64_MAX) bad(`${key} is out of range for a 64-bit whole number, got "${v}".`)
        else if (n < BigInt(min)) bad(`${key} must be a whole number >= ${min}, got "${v}".`)
        else if (def.max !== undefined && n > BigInt(def.max)) bad(`${key} must be a whole number <= ${def.max}, got "${v}".`)
      }
    } else if (def.kind === 'duration') {
      const ms = durationMs(v)
      if (ms === null) {
        out.push({ id: `bad-duration-${key}`, level: 'error', message: `${key} must be a duration such as 30s or 1h, got "${v}".` })
      } else if (ms <= 0 && mustBePositive(def)) {
        out.push({ id: `bad-duration-${key}`, level: 'error', message: `${key} must be greater than zero, got "${v}".` })
      } else if (hasCooldownCap(def) && (durationNs(v) ?? BigInt(0)) > MAX_COOLDOWN_NS) {
        out.push({ id: `bad-duration-${key}`, level: 'error', message: `${key} must not exceed ${MAX_COOLDOWN}, got "${v}"; use a value up to ${MAX_COOLDOWN}.` })
      }
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
  const proxyAll = BOOL_ON.includes(proxyRaw)
  const proxyList = proxyAll || BOOL_OFF.includes(proxyRaw) || proxyRaw === ''
    ? []
    : proxyRaw.split(',').map((p) => p.trim()).filter((p) => p !== '')
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
  const trustedParsed = trusted === 'any' ? { count: 1 } : parseIgnoreList(trusted)
  // An unparsable list is reported by checkValues; here only "empty" matters.
  const trustedEmpty = 'count' in trustedParsed && trustedParsed.count === 0
  if (proxyActive && trustedEmpty) {
    out.push({ id: 'proxy-no-trusted', level: 'error', message: 'RAN_PROXY_TRUSTED is required when PROXY protocol is used; list the proxy addresses or ranges.' })
  }
  if (!proxyActive && !trustedEmpty) {
    out.push({ id: 'trusted-without-proxy', level: 'warning', message: 'RAN_PROXY_TRUSTED is set but no trap uses PROXY protocol, so it has no effect.' })
  }

  // Cooldowns (same wording as config.CooldownWarnings)
  const alertMs = durationMs(get('RAN_ALERT_COOLDOWN'))
  const repeatMs = durationMs(get('RAN_REPEAT_COOLDOWN'))
  if (alertMs !== null && alertMs <= 0) {
    if (isTruthy(get('RAN_SHUN'))) {
      out.push({ id: 'shun-without-cooldown', level: 'warning', message: 'RAN_SHUN has no effect while RAN_ALERT_COOLDOWN is 0s; a shun window lasts for the alert cooldown.' })
    }
    if (repeatMs !== null && repeatMs > 0) {
      out.push({ id: 'repeat-without-cooldown', level: 'warning', message: 'RAN_REPEAT_COOLDOWN has no effect while RAN_ALERT_COOLDOWN is 0s, because the cooldown is disabled.' })
    }
  } else if (alertMs !== null && repeatMs !== null && repeatMs > 0 && repeatMs < alertMs) {
    out.push({ id: 'repeat-below-cooldown', level: 'warning', message: 'RAN_REPEAT_COOLDOWN is smaller than RAN_ALERT_COOLDOWN; the repeat cooldown is meant to be longer than the base cooldown.' })
  }

  // UDP rate (exact comparison: values may exceed 2^53)
  const burstText = get('RAN_UDP_RATE_BURST').trim()
  const rateText = get('RAN_UDP_RATE_PER_SOURCE').trim()
  if (/^[+-]?\d+$/.test(burstText) && /^[+-]?\d+$/.test(rateText) && BigInt(burstText) < BigInt(rateText)) {
    out.push({ id: 'udp-burst-below-rate', level: 'error', message: `RAN_UDP_RATE_BURST (${BigInt(burstText)}) must not be smaller than RAN_UDP_RATE_PER_SOURCE (${BigInt(rateText)}).` })
  }

  // Addressless traps need their address variable
  for (const name of traps) {
    const trap = findTrap(reg, name)
    if (trap?.addressless && (env[trap.addr_var] ?? '').trim() === '') {
      out.push({ id: `addr-required-${name}`, level: 'error', message: `${trap.addr_var} is required when ${name} is enabled in RAN_TRAPS.` })
    }
  }

  // CrowdSec
  if (isTruthy(get('RAN_SHUN')) && !crowdsecOn(reg, env)) {
    out.push({ id: 'shun-without-crowdsec', level: 'warning', message: 'RAN_SHUN has no effect without RAN_CROWDSEC; shunning starts after an accepted alert.' })
  }
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
  if ((env.RAN_PROXY_TRUSTED ?? '').trim() === 'any') {
    out.push({
      id: 'trusted-any',
      message: 'RAN_PROXY_TRUSTED=any lets every peer send a PROXY header and so spoof the client address. Use a narrow list plus a firewall.'
    })
  }
  return out
}
