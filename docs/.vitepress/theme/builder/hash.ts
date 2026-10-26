import type { BuilderState } from './types'
import { SECRET_KEYS } from './types'
import type { Register } from './types'
import { defaultState, findTrap, resolveSetting, setValue } from './state'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

const MAX_ENTRIES = 400
/** Longest accepted value; banner services need about 3000, fixtures are bounded by the URL anyway. */
const MAX_VALUE = 16384
/** Longest accepted decoded JSON (bytes). */
const MAX_JSON = 256 * 1024

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
  /** Legacy scenario field from old share links; ignored on decode. */
  s?: string
  p?: string[]
}

/** Compact JSON of the non-default state, as base64url. */
export function encodeState(state: BuilderState): string {
  const c: Compact = { t: state.traps }
  const values = { ...state.values }
  for (const k of SECRET_KEYS) delete values[k]
  if (Object.keys(values).length > 0) c.v = values
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


/** Why a share link could not be used; null when it loaded (possibly with dropped entries). */
export type ShareProblem = 'invalid' | 'too-large' | null

export interface ShareResult {
  state: BuilderState
  problem: ShareProblem
  /** Traps and keys that were left out because the register does not know them. */
  dropped: string[]
}

export const SHARE_PROBLEM_TEXT = 'Share link could not be loaded, using defaults.'

function fail(problem: Exclude<ShareProblem, null>): ShareResult {
  return { state: defaultState(), problem, dropped: [] }
}

/**
 * Never throws: anything unusable yields the default state plus a reason.
 * Values are sanitized, unknown traps and variables are dropped (and listed).
 */
export function decodeShare(hash: string, reg: Register): ShareResult {
  try {
    const text = hash.replace(/^#/, '').trim()
    if (text === '') return { state: defaultState(), problem: null, dropped: [] }
    const bytes = base64UrlToBytes(text)
    if (!bytes) return fail('invalid')
    if (bytes.length > MAX_JSON) return fail('too-large')
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return fail('invalid')
    const c = parsed as Record<string, unknown>
    const rawTraps = c.t === undefined ? [] : names(c.t)
    const rawProxied = c.p === undefined ? [] : names(c.p)
    if (!rawTraps || !rawProxied) return fail('invalid')
    const dropped: string[] = []
    const known = (list: string[]) =>
      list.filter((n) => {
        if (findTrap(reg, n)) return true
        dropped.push(n)
        return false
      })
    const traps = [...new Set(known(rawTraps))]
    const proxied = [...new Set(known(rawProxied))].filter((n) => traps.includes(n))
    let state: BuilderState = { traps, values: {}, proxied }
    if (c.v !== undefined) {
      if (typeof c.v !== 'object' || c.v === null || Array.isArray(c.v)) return fail('invalid')
      const entries = Object.entries(c.v as Record<string, unknown>)
      if (entries.length > MAX_ENTRIES) return fail('too-large')
      for (const [k, v] of entries) {
        if (typeof v !== 'string' || !/^RAN_[A-Z0-9_]{1,80}$/.test(k)) return fail('invalid')
        if (v.length > MAX_VALUE) return fail('too-large')
        if (SECRET_KEYS.includes(k) || k === 'RAN_TRAPS') continue
        if (!resolveSetting(reg, k)) {
          dropped.push(k)
          continue
        }
        state = setValue(reg, state, k, v)
      }
    }
    // Legacy share links may carry a scenario field (s); it is silently ignored.
    return { state, problem: null, dropped }
  } catch {
    return fail('invalid')
  }
}

export function decodeState(hash: string, reg: Register): BuilderState {
  return decodeShare(hash, reg).state
}
