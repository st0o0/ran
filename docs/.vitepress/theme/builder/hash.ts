import type { BuilderState, ScenarioId } from './types'
import { SECRET_KEYS } from './types'
import { defaultState } from './state'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const SCENARIOS: ScenarioId[] = ['direct', 'reverse-proxy', 'shared-namespace', 'crowdsec']

const MAX_ENTRIES = 400
const MAX_VALUE = 4000

/** base64url without padding, straight from UTF-8 bytes (no btoa). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0
    out += ALPHABET[b0 >> 2]
    out += ALPHABET[((b0 & 3) << 4) | (b1 >> 4)]
    if (i + 1 < bytes.length) out += ALPHABET[((b1 & 15) << 2) | (b2 >> 6)]
    if (i + 2 < bytes.length) out += ALPHABET[b2 & 63]
  }
  return out
}

/** Returns null for any character outside the alphabet or an impossible length. */
export function base64UrlToBytes(text: string): Uint8Array | null {
  if (text.length % 4 === 1) return null
  const vals: number[] = []
  for (const ch of text) {
    const v = ALPHABET.indexOf(ch)
    if (v < 0) return null
    vals.push(v)
  }
  const out: number[] = []
  for (let i = 0; i < vals.length; i += 4) {
    const n = vals.length - i
    const v0 = vals[i]
    const v1 = vals[i + 1]
    const v2 = n > 2 ? vals[i + 2] : 0
    const v3 = n > 3 ? vals[i + 3] : 0
    out.push((v0 << 2) | (v1 >> 4))
    if (n > 2) out.push(((v1 & 15) << 4) | (v2 >> 2))
    if (n > 3) out.push(((v2 & 3) << 6) | v3)
  }
  return Uint8Array.from(out)
}

interface Compact {
  t?: string[]
  v?: Record<string, string>
  s?: string
  p?: string[]
}

/** Compact JSON of the non-default state, as base64url. */
export function encodeState(state: BuilderState): string {
  const c: Compact = { t: state.traps }
  const values = { ...state.values }
  for (const k of SECRET_KEYS) delete values[k]
  if (Object.keys(values).length > 0) c.v = values
  if (state.scenario !== 'direct') c.s = state.scenario
  if (state.proxied.length > 0) c.p = state.proxied
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(c)))
}

function names(x: unknown): string[] | null {
  if (!Array.isArray(x) || x.length > MAX_ENTRIES) return null
  const out: string[] = []
  for (const e of x) {
    if (typeof e !== 'string' || !/^[a-z0-9]{1,32}$/.test(e)) return null
    out.push(e)
  }
  return out
}

/** Never throws: anything unusable yields the default state. */
export function decodeState(hash: string): BuilderState {
  try {
    const text = hash.replace(/^#/, '').trim()
    if (text === '') return defaultState()
    const bytes = base64UrlToBytes(text)
    if (!bytes) return defaultState()
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return defaultState()
    const c = parsed as Record<string, unknown>
    const traps = c.t === undefined ? [] : names(c.t)
    const proxied = c.p === undefined ? [] : names(c.p)
    if (!traps || !proxied) return defaultState()
    const values: Record<string, string> = {}
    if (c.v !== undefined) {
      if (typeof c.v !== 'object' || c.v === null || Array.isArray(c.v)) return defaultState()
      const entries = Object.entries(c.v as Record<string, unknown>)
      if (entries.length > MAX_ENTRIES) return defaultState()
      for (const [k, v] of entries) {
        if (typeof v !== 'string' || v.length > MAX_VALUE || !/^RAN_[A-Z0-9_]{1,80}$/.test(k)) {
          return defaultState()
        }
        if (SECRET_KEYS.includes(k) || k === 'RAN_TRAPS') continue
        values[k] = v
      }
    }
    const scenario = c.s === undefined ? 'direct' : c.s
    if (typeof scenario !== 'string' || !SCENARIOS.includes(scenario as ScenarioId)) {
      return defaultState()
    }
    return { traps, values, scenario: scenario as ScenarioId, proxied }
  } catch {
    return defaultState()
  }
}
