import type { Register, SettingDef, TrapDef } from './types'
import { familyKey } from './state'

export interface TrapGroup {
  id: string
  title: string
  note?: string
  traps: TrapDef[]
}

const REMOTE = ['ssh', 'telnet', 'rdp', 'vnc', 'ftp', 'adb', 'smb']
const DATABASES = ['mysql', 'postgres', 'mssql', 'oracle', 'mongodb', 'redis', 'memcached', 'elasticsearch']
const WEB = ['http', 'https', 'httpproxy', 'docker', 'kubernetes', 'mcp']
const ICS = ['modbus', 's7comm', 'enip', 'ipp', 'pjl']

/** Groups derived from names and transport; unlisted traps fall into "Other". */
export function trapGroups(reg: Register): TrapGroup[] {
  const udp = reg.traps.filter((t) => t.transport === 'UDP')
  const tcp = reg.traps.filter((t) => t.transport !== 'UDP')
  const pick = (names: string[]) => tcp.filter((t) => names.includes(t.name))
  const used = new Set([...REMOTE, ...DATABASES, ...WEB, ...ICS])
  return [
    { id: 'remote', title: 'Remote access', traps: pick(REMOTE) },
    { id: 'databases', title: 'Databases and caches', traps: pick(DATABASES) },
    { id: 'web', title: 'Web and APIs', traps: pick(WEB) },
    { id: 'ics', title: 'ICS and printers', traps: pick(ICS) },
    { id: 'udp', title: 'UDP', note: 'log only, never alerts', traps: udp },
    { id: 'other', title: 'Other', traps: tcp.filter((t) => !used.has(t.name)) }
  ].filter((g) => g.traps.length > 0)
}

export interface SettingGroup {
  id: string
  title: string
  advanced: boolean
  settings: SettingDef[]
}

const GROUP_ORDER: Array<[string, string, boolean]> = [
  ['core', 'General', false],
  ['proxy', 'PROXY protocol', false],
  ['crowdsec', 'CrowdSec', false],
  ['ignore', 'Ignore list', false],
  ['http', 'HTTP', false],
  ['ssh', 'SSH', false],
  ['logging', 'Logging', true],
  ['limits', 'Limits', true],
  ['udp', 'UDP rate limits', true],
  ['fingerprint', 'Fingerprint', true]
]

/** Variables handled elsewhere in the page: the trap picker, per-trap fields and secrets. */
const HIDDEN = ['RAN_TRAPS', 'RAN_CROWDSEC_PASSWORD', 'RAN_BANNER_SERVICES']

export function settingGroups(reg: Register): SettingGroup[] {
  const plain = reg.settings.filter((s) => !s.family && !HIDDEN.includes(s.name))
  const known = new Set(GROUP_ORDER.map((g) => g[0]))
  const groups: SettingGroup[] = GROUP_ORDER.map(([id, title, advanced]) => ({
    id,
    title,
    advanced,
    settings: plain.filter((s) => s.group === id)
  }))
  // A group the builder does not know yet still shows up, collapsed.
  for (const s of plain.filter((x) => !known.has(x.group))) {
    let g = groups.find((x) => x.id === s.group)
    if (!g) {
      g = { id: s.group, title: s.group, advanced: true, settings: [] }
      groups.push(g)
    }
    g.settings.push(s)
  }
  return groups.filter((g) => g.settings.length > 0)
}

export interface TrapField {
  key: string
  def: SettingDef
  placeholder: string
}

/** Per-trap fields: listen address, auth and timeout overrides, banner services. */
export function trapFields(reg: Register, trap: string): TrapField[] {
  const def = reg.traps.find((t) => t.name === trap)
  const out: TrapField[] = []
  if (trap === 'banner') {
    const s = reg.settings.find((x) => x.name === 'RAN_BANNER_SERVICES')
    if (s) out.push({ key: s.name, def: s, placeholder: '2222=ssh:SSH-2.0-OpenSSH_9.6' })
  }
  for (const s of reg.settings) {
    if (!s.family || !(s.traps ?? []).includes(trap)) continue
    out.push({
      key: familyKey(trap, s.family),
      def: s,
      placeholder: s.family === 'ADDR' ? def?.default_addr || ':4444' : 'inherit'
    })
  }
  return out
}
