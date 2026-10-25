// IP and CIDR parsing that follows Go's net/netip (ParseAddr, ParsePrefix) and
// config.ParseIgnoreList, which RAN_IGNORE_IPS and RAN_PROXY_TRUSTED use.
// Framework free.

export const MAX_IGNORE_ENTRIES = 1024

/** Bytes of an address: 4 (IPv4) or 16 (IPv6). Zones are not supported. */
function parseV4(s: string): number[] | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const out: number[] = []
  for (const p of parts) {
    // 1 to 3 digits, no leading zeros (Go rejects "01"), value <= 255
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    out.push(n)
  }
  return out
}

function parseV6(input: string): number[] | null {
  let s = input
  const ip = new Array<number>(16).fill(0)
  let ellipsis = -1
  if (s.startsWith('::')) {
    ellipsis = 0
    s = s.slice(2)
    if (s === '') return ip
  }
  let i = 0
  while (i < 16) {
    let off = 0
    let acc = 0
    while (off < s.length && /[0-9a-fA-F]/.test(s[off])) {
      acc = (acc << 4) + parseInt(s[off], 16)
      off++
      if (off > 4) return null
    }
    if (off === 0) return null
    if (off < s.length && s[off] === '.') {
      if (ellipsis < 0 && i !== 12) return null
      if (i + 4 > 16) return null
      const v4 = parseV4(s)
      if (!v4) return null
      for (let k = 0; k < 4; k++) ip[i + k] = v4[k]
      s = ''
      i += 4
      break
    }
    ip[i] = (acc >> 8) & 0xff
    ip[i + 1] = acc & 0xff
    i += 2
    s = s.slice(off)
    if (s === '') break
    if (s[0] !== ':' || s.length === 1) return null
    s = s.slice(1)
    if (s[0] === ':') {
      if (ellipsis >= 0) return null
      ellipsis = i
      s = s.slice(1)
      if (s === '') break
    }
  }
  if (s !== '') return null
  if (i < 16) {
    if (ellipsis < 0) return null
    const n = 16 - i
    for (let j = i - 1; j >= ellipsis; j--) ip[j + n] = ip[j]
    for (let j = ellipsis + n - 1; j >= ellipsis; j--) ip[j] = 0
  } else if (ellipsis >= 0) {
    return null
  }
  return ip
}

/** Parses an IP address; zones ("%eth0") are rejected like the ignore list does. */
export function parseIp(s: string): number[] | null {
  const m = /[.:%]/.exec(s)
  if (!m) return null
  if (m[0] === '.') return parseV4(s)
  if (m[0] === ':') return s.includes('%') ? null : parseV6(s)
  return null
}

function isMapped(b: number[]): boolean {
  if (b.length !== 16) return false
  for (let i = 0; i < 10; i++) if (b[i] !== 0) return false
  return b[10] === 0xff && b[11] === 0xff
}

function mask(b: number[], bits: number): number[] {
  return b.map((v, i) => {
    const keep = Math.max(0, Math.min(8, bits - i * 8))
    return keep === 8 ? v : v & (0xff << (8 - keep)) & 0xff
  })
}

/**
 * Normalized key of one ignore-list entry (family, masked address, prefix length),
 * or an error text. IPv4-mapped forms become IPv4, CIDRs are masked.
 */
export function parseIgnoreEntry(s: string): { key: string } | { error: string } {
  let addr: number[] | null
  let bits: number
  if (s.includes('/')) {
    const i = s.lastIndexOf('/')
    addr = parseIp(s.slice(0, i))
    const bitsText = s.slice(i + 1)
    if (!addr) return { error: 'invalid address' }
    if (!/^(0|[1-9]\d*)$/.test(bitsText)) return { error: 'bad prefix length' }
    bits = Number(bitsText)
    if (bits > addr.length * 8) return { error: 'prefix length too large' }
    if (isMapped(addr)) {
      if (bits < 96) return { error: 'IPv4-mapped ranges need a prefix length of at least 96' }
      addr = addr.slice(12)
      bits -= 96
    }
  } else {
    addr = parseIp(s)
    if (!addr) return { error: 'invalid address' }
    if (isMapped(addr)) addr = addr.slice(12)
    bits = addr.length * 8
  }
  return { key: `${addr.length}/${mask(addr, bits).join('.')}/${bits}` }
}

export type IgnoreListResult = { count: number } | { error: string; bad?: string }

/** Mirrors config.ParseIgnoreList: counts the distinct entries or reports the first problem. */
export function parseIgnoreList(raw: string): IgnoreListResult {
  const seen = new Set<string>()
  for (let part of raw.split(',')) {
    part = part.trim()
    if (part === '') continue
    const r = parseIgnoreEntry(part)
    if ('error' in r) return { error: r.error, bad: part }
    if (!seen.has(r.key)) {
      if (seen.size >= MAX_IGNORE_ENTRIES) return { error: 'limit' }
      seen.add(r.key)
    }
  }
  return { count: seen.size }
}
