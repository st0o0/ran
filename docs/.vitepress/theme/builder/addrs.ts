import type { Register } from './types'
import { findTrap } from './state'

/** Spellings of the Go boolean reader (envReader.boolean), compared case-insensitively. */
export const BOOL_ON = ['on', 'true', 'yes', '1']
export const BOOL_OFF = ['off', 'false', 'no', '0']

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
