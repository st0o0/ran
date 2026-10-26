import {
  type BuilderState,
  type Format,
  type ImportResult,
  type Output,
  type Register,
  PASSWORD_PLACEHOLDER,
  SECRET_KEYS
} from './types'
import { BOOL_OFF, BOOL_ON, trapAddrs } from './addrs'
import {
  crowdsecOn,
  defaultState,
  effectiveEnv,
  findTrap,
  resolveSetting,
  setValue,
  sortKeys,
  splitList,
  usesProxyList
} from './state'

export const IMAGE = 'ghcr.io/st0o0/ran:latest'
export const DATA_VOLUME = 'ran-data'

const PASSWORD_NOTE =
  'RAN_CROWDSEC_PASSWORD is a placeholder (CHANGE_ME). Replace it with the machine password from "cscli machines add"; the builder never asks for it.'
const PASSWORD_COMMENT = 'Replace CHANGE_ME with the machine password (cscli machines add).'

export interface Export {
  /** Variables in stable order, secrets replaced by a placeholder. */
  env: Array<[string, string]>
  notes: string[]
}

/** Delta-only export: only values that differ from the default. */
export function exportEnv(reg: Register, state: BuilderState): Export {
  const env = effectiveEnv(state)
  const notes: string[] = []
  if (crowdsecOn(reg, env)) {
    env.RAN_CROWDSEC_PASSWORD = PASSWORD_PLACEHOLDER
    notes.push(PASSWORD_NOTE)
  }
  const keys = sortKeys(reg, Object.keys(env))
  return { env: keys.map((k) => [k, env[k]] as [string, string]), notes }
}

export interface PortMapping {
  /** Published as "host:container/proto" (host side bound to loopback for metrics). */
  spec: string
  label: string
}

/** Published ports derived from the enabled traps, their transport and listen addresses. */
export function portMappings(reg: Register, state: BuilderState): PortMapping[] {
  const env = effectiveEnv(state)
  const out: PortMapping[] = []
  const seen = new Set<string>()
  const proxied = usesProxyList(state) ? state.proxied : []
  for (const name of state.traps) {
    const trap = findTrap(reg, name)
    // A proxied trap must not also be published: direct connections to it are dropped.
    if (!trap || proxied.includes(name)) continue
    const proto = trap.transport === 'UDP' ? 'udp' : 'tcp'
    for (const a of trapAddrs(reg, env, name)) {
      const spec = proto === 'udp' ? `${a.port}:${a.port}/udp` : `${a.port}:${a.port}`
      if (seen.has(spec)) continue
      seen.add(spec)
      out.push({ spec, label: name })
    }
  }
  // Metrics stay on the loopback interface of the host.
  const metrics = env.RAN_METRICS_ADDR ?? resolveSetting(reg, 'RAN_METRICS_ADDR')?.def.default ?? ''
  const m = /:(\d+)$/.exec(metrics)
  if (m) out.push({ spec: `127.0.0.1:${m[1]}:${m[1]}`, label: 'metrics' })
  return out
}

const PLAIN_VALUE = /^[A-Za-z0-9_@%+=:,./-]+$/

/**
 * Quotes one env file value by docker compose .env rules: bare when it only has
 * safe characters, single quotes (literal, no interpolation) otherwise, and
 * double quotes with backslash escapes when the value itself holds a single quote.
 */
export function envQuote(v: string): string {
  if (PLAIN_VALUE.test(v)) return v
  if (!v.includes("'")) return `'${v}'`
  return '"' + v.replace(/[\\"$]/g, (c) => '\\' + c) + '"'
}

const ENV_QUOTE_NOTE =
  'Quoted values follow docker compose .env rules (env_file or --env-file of docker compose). "docker run --env-file" keeps the quotes literally: use the docker run output instead.'

export function toEnvFile(reg: Register, state: BuilderState): Output {
  const { env, notes } = exportEnv(reg, state)
  const lines: string[] = []
  let quoted = false
  for (const [k, v] of env) {
    if (SECRET_KEYS.includes(k)) lines.push(`# ${PASSWORD_COMMENT}`)
    const q = envQuote(v)
    if (q !== v) quoted = true
    lines.push(`${k}=${q}`)
  }
  if (quoted) lines.unshift(`# ${ENV_QUOTE_NOTE}`)
  return { text: lines.join('\n') + (lines.length ? '\n' : ''), notes }
}

/** Comment lines (without the comment marker) about proxied traps and how the proxy reaches ran. */
export function proxyComment(reg: Register, state: BuilderState): string[] {
  if (!usesProxyList(state)) return []
  const env = effectiveEnv(state)
  const shared = (env.RAN_PROXY_TRUSTED ?? '') === '127.0.0.1,::1'
  const where = state.proxied
    .map((t) => {
      const ports = trapAddrs(reg, env, t).map((a) => a.port)
      return `${t} (${ports.map((p) => `${shared ? '127.0.0.1' : 'ran'}:${p}`).join(', ')})`
    })
    .join(', ')
  return shared
    ? [
        `Proxied traps are not published: ${where}.`,
        'The proxy shares this network namespace and reaches ran on loopback; it must send a PROXY v2 header.'
      ]
    : [
        `Proxied traps are not published: ${where}.`,
        'The proxy reaches ran at ran:<port> inside this compose network (same network, service name ran) and must send a PROXY v2 header.'
      ]
}

/** Comment lines about the CrowdSec LAPI; empty when CrowdSec is off. */
export function crowdsecComment(reg: Register, state: BuilderState, format: 'compose' | 'run'): string[] {
  const env = effectiveEnv(state)
  if (!crowdsecOn(reg, env)) return []
  const url = env.RAN_CROWDSEC_URL || '<RAN_CROWDSEC_URL>'
  return [
    `CrowdSec: a LAPI must be reachable under the hostname in RAN_CROWDSEC_URL (${url}) on the same Docker network as this container.`,
    format === 'run'
      ? 'Put both containers on one network and add --network <name> to this command and to the LAPI container.'
      : 'Run the LAPI as another service of this file or attach both to one shared network.',
    'The first failed LAPI login is fatal: ran exits at startup if the LAPI is unreachable or the credentials are wrong.',
    PASSWORD_COMMENT
  ]
}

export function toCompose(reg: Register, state: BuilderState): Output {
  const { env, notes } = exportEnv(reg, state)
  const ports = portMappings(reg, state)
  const l: string[] = []
  l.push('services:')
  for (const c of [...crowdsecComment(reg, state, 'compose'), ...proxyComment(reg, state)]) l.push(`  # ${c}`)
  l.push('  ran:')
  l.push(`    image: ${IMAGE}`)
  l.push('    restart: unless-stopped')
  l.push('    read_only: true')
  l.push('    cap_drop: [ALL]')
  l.push('    security_opt:')
  l.push('      - no-new-privileges:true')
  l.push('    user: "65532:65532"')
  if (env.length > 0) {
    l.push('    environment:')
    for (const [k, v] of env) {
      if (SECRET_KEYS.includes(k)) l.push(`      # ${PASSWORD_COMMENT}`)
      // Compose interpolates $ in values; $$ is a literal dollar sign.
      l.push(`      ${k}: ${JSON.stringify(v.split('$').join('$$'))}`)
    }
  }
  if (ports.length > 0) {
    l.push('    ports:')
    for (const p of ports) l.push(`      - ${JSON.stringify(p.spec)}   # ${p.label}`)
  }
  l.push('    volumes:')
  l.push(`      - ${DATA_VOLUME}:/data   # SSH host key, HTTPS certificate, fingerprint seed`)
  l.push('    tmpfs:')
  l.push('      - /tmp')
  l.push('volumes:')
  l.push(`  ${DATA_VOLUME}:`)
  return { text: l.join('\n') + '\n', notes }
}

export function shellQuote(v: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(v)) return v
  return "'" + v.split("'").join("'\\''") + "'"
}

export function toDockerRun(reg: Register, state: BuilderState): Output {
  const { env, notes } = exportEnv(reg, state)
  const ports = portMappings(reg, state)
  const comments = [...crowdsecComment(reg, state, 'run'), ...proxyComment(reg, state)]
  const parts: string[] = [
    'docker run -d --name ran',
    '--restart unless-stopped',
    '--read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 --tmpfs /tmp',
    `-v ${DATA_VOLUME}:/data`
  ]
  for (const [k, v] of env) parts.push(`-e ${shellQuote(`${k}=${v}`)}`)
  if (ports.length > 0) parts.push(ports.map((p) => `-p ${p.spec}`).join(' '))
  parts.push(IMAGE)
  const head = comments.map((c) => `# ${c}\n`).join('')
  return { text: head + parts.join(' \\\n  ') + '\n', notes }
}

export function serialize(reg: Register, state: BuilderState, format: Format): Output {
  if (format === 'compose') return toCompose(reg, state)
  if (format === 'run') return toDockerRun(reg, state)
  return toEnvFile(reg, state)
}

/** Parses an env file. Comments and blank lines are skipped, unknown keys are reported. */
export function importEnv(reg: Register, text: string): ImportResult {
  const unknown: string[] = []
  const ignored: string[] = []
  let state = defaultState()
  const raw: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    let l = line.trim()
    if (l === '' || l.startsWith('#')) continue
    if (l.startsWith('export ')) l = l.slice(7).trim()
    const eq = l.indexOf('=')
    if (eq <= 0) {
      unknown.push(l)
      continue
    }
    const key = l.slice(0, eq).trim()
    let value = l.slice(eq + 1).trim()
    const q = value[0]
    if (value.length >= 2 && (q === '"' || q === "'") && value[value.length - 1] === q) {
      value = value.slice(1, -1)
      if (q === '"') value = value.replace(/\\([\\"$])/g, '$1')
    }
    if (SECRET_KEYS.includes(key)) {
      ignored.push(key)
      continue
    }
    if (key === 'RAN_TRAPS' || resolveSetting(reg, key)) raw[key] = value
    else unknown.push(key)
  }

  state.traps = splitList(raw.RAN_TRAPS ?? '').map((t) => t.toLowerCase())
  for (const [key, value] of Object.entries(raw)) {
    if (key === 'RAN_TRAPS') continue
    if (key === 'RAN_PROXY_PROTOCOL') {
      const v = value.trim().toLowerCase()
      if (BOOL_ON.includes(v) || BOOL_OFF.includes(v) || v === '') {
        state = setValue(reg, state, key, v)
      } else {
        state.proxied = v.split(',').map((x) => x.trim()).filter((x) => x !== '')
      }
      continue
    }
    state = setValue(reg, state, key, value)
  }
  return { state, unknown, ignored }
}
