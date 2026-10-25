import {
  type BuilderState,
  type Register,
  type SettingDef,
  type TrapDef,
  SECRET_KEYS
} from './types'

export const DEFAULT_TRAPS = ['ssh', 'http']

export function defaultState(): BuilderState {
  return { traps: [...DEFAULT_TRAPS], values: {}, scenario: 'direct', proxied: [] }
}

export function cloneState(s: BuilderState): BuilderState {
  return {
    traps: [...s.traps],
    values: { ...s.values },
    scenario: s.scenario,
    proxied: [...s.proxied]
  }
}

export function findTrap(reg: Register, name: string): TrapDef | undefined {
  return reg.traps.find((t) => t.name === name)
}

export function isUdp(reg: Register, name: string): boolean {
  return findTrap(reg, name)?.transport === 'UDP'
}

export function familyKey(trap: string, family: string): string {
  return `RAN_${trap.toUpperCase()}_${family}`
}

/** Finds the register entry for a variable name, resolving per-trap families. */
export function resolveSetting(
  reg: Register,
  key: string
): { def: SettingDef; trap?: string } | undefined {
  const exact = reg.settings.find((s) => !s.family && s.name === key)
  if (exact) return { def: exact }
  for (const def of reg.settings) {
    if (!def.family) continue
    for (const trap of def.traps ?? []) {
      if (familyKey(trap, def.family) === key) return { def, trap }
    }
  }
  return undefined
}

export function defaultOf(reg: Register, key: string): string {
  const hit = resolveSetting(reg, key)
  if (!hit) return ''
  if (hit.def.family === 'ADDR' && hit.trap) return findTrap(reg, hit.trap)?.default_addr ?? ''
  return hit.def.default
}

function sanitize(v: string): string {
  return v.replace(/[\r\n]+/g, ' ').trim()
}

export function setTrap(s: BuilderState, name: string, on: boolean): BuilderState {
  const next = cloneState(s)
  const has = next.traps.includes(name)
  if (on && !has) next.traps.push(name)
  if (!on && has) {
    next.traps = next.traps.filter((t) => t !== name)
    next.proxied = next.proxied.filter((t) => t !== name)
  }
  return next
}

export function setProxied(s: BuilderState, name: string, on: boolean): BuilderState {
  const next = cloneState(s)
  const has = next.proxied.includes(name)
  if (on && !has) next.proxied.push(name)
  if (!on && has) next.proxied = next.proxied.filter((t) => t !== name)
  return next
}

/** Stores a value; a value equal to the default (or empty) removes the entry. */
export function setValue(
  reg: Register,
  s: BuilderState,
  key: string,
  raw: string
): BuilderState {
  const next = cloneState(s)
  if (key === 'RAN_TRAPS' || SECRET_KEYS.includes(key)) return next
  const value = sanitize(raw)
  if (value === '' || value === defaultOf(reg, key)) delete next.values[key]
  else next.values[key] = value
  return next
}

export function usesProxyList(s: BuilderState): boolean {
  return (s.scenario === 'reverse-proxy' || s.scenario === 'shared-namespace') && s.proxied.length > 0
}

/** Variables that differ from the default, as the sensor would see them (secrets excluded). */
export function effectiveEnv(s: BuilderState): Record<string, string> {
  const env: Record<string, string> = { ...s.values }
  for (const k of SECRET_KEYS) delete env[k]
  if (s.traps.length > 0) env.RAN_TRAPS = s.traps.join(',')
  if (usesProxyList(s)) env.RAN_PROXY_PROTOCOL = s.proxied.join(',')
  return env
}

export function envGet(reg: Register, env: Record<string, string>, key: string): string {
  const v = env[key]
  return v !== undefined ? v : defaultOf(reg, key)
}

const OFF = ['', 'off', 'false', '0', 'no']

export function isTruthy(v: string): boolean {
  return !OFF.includes(v.trim().toLowerCase())
}

/** True when every variable the setting requires is switched on. */
export function isActive(reg: Register, def: SettingDef, env: Record<string, string>): boolean {
  return (def.requires ?? []).every((r) => isTruthy(envGet(reg, env, r)))
}

export function crowdsecOn(reg: Register, env: Record<string, string>): boolean {
  return isTruthy(envGet(reg, env, 'RAN_CROWDSEC'))
}

function rank(reg: Register, key: string): number {
  if (key === 'RAN_TRAPS') return -1
  const idx = reg.settings.findIndex((s) => {
    if (!s.family) return s.name === key
    return (s.traps ?? []).some((t) => familyKey(t, s.family as string) === key)
  })
  return idx < 0 ? reg.settings.length : idx
}

export function sortKeys(reg: Register, keys: string[]): string[] {
  return [...keys].sort((a, b) => {
    const d = rank(reg, a) - rank(reg, b)
    return d !== 0 ? d : a < b ? -1 : a > b ? 1 : 0
  })
}

export function splitList(v: string): string[] {
  return v
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter((x) => x !== '')
}

/** Equal states produce the same export; used for round trip checks. */
export function sameState(a: BuilderState, b: BuilderState): boolean {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b))
}

function canon(s: BuilderState) {
  return {
    traps: [...s.traps].sort(),
    proxied: [...s.proxied].sort(),
    scenario: s.scenario,
    values: Object.fromEntries(Object.entries(s.values).sort(([a], [b]) => (a < b ? -1 : 1)))
  }
}
