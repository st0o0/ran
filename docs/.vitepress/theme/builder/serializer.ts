import {
  type BuilderState,
  type Format,
  type ImportResult,
  type Output,
  type Register,
  PASSWORD_PLACEHOLDER,
  SECRET_KEYS
} from './types'
import { trapAddrs } from './rules'
import {
  crowdsecOn,
  defaultState,
  effectiveEnv,
  findTrap,
  resolveSetting,
  setValue,
  sortKeys,
  splitList
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
  for (const name of state.traps) {
    const trap = findTrap(reg, name)
    if (!trap) continue
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

export function toEnvFile(reg: Register, state: BuilderState): Output {
  const { env, notes } = exportEnv(reg, state)
  const lines: string[] = []
  for (const [k, v] of env) {
    if (SECRET_KEYS.includes(k)) lines.push(`# ${PASSWORD_COMMENT}`)
    lines.push(`${k}=${v}`)
  }
  return { text: lines.join('\n') + (lines.length ? '\n' : ''), notes }
}

export function toCompose(reg: Register, state: BuilderState): Output {
  const { env, notes } = exportEnv(reg, state)
  const ports = portMappings(reg, state)
  const l: string[] = []
  l.push('services:')
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
      l.push(`      ${k}: ${JSON.stringify(v)}`)
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
  const parts: string[] = [
    'docker run -d --name ran',
    '--restart unless-stopped',
    '--read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 --tmpfs /tmp',
    `-v ${DATA_VOLUME}:/data`
  ]
  for (const [k, v] of env) parts.push(`-e ${shellQuote(`${k}=${v}`)}`)
  if (ports.length > 0) parts.push(ports.map((p) => `-p ${p.spec}`).join(' '))
  parts.push(IMAGE)
  return { text: parts.join(' \\\n  ') + '\n', notes }
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
      if (v === 'on' || v === 'off' || v === '') {
        state = setValue(reg, state, key, v)
      } else {
        state.proxied = splitList(v)
        state.scenario = 'reverse-proxy'
      }
      continue
    }
    state = setValue(reg, state, key, value)
  }
  if (state.scenario === 'reverse-proxy' && state.values.RAN_PROXY_TRUSTED === '127.0.0.1,::1') {
    state.scenario = 'shared-namespace'
  } else if (state.scenario === 'direct' && crowdsecOn(reg, effectiveEnv(state))) {
    state.scenario = 'crowdsec'
  }
  return { state, unknown, ignored }
}
