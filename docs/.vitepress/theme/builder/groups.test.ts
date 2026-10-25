import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import type { Register } from './types'
import { settingGroups, trapFields, trapGroups } from './groups'

const reg = settingsJson as unknown as Register

describe('groups', () => {
  it('places every trap in exactly one group', () => {
    const names = trapGroups(reg).flatMap((g) => g.traps.map((t) => t.name))
    expect([...names].sort()).toEqual(reg.traps.map((t) => t.name).sort())
  })

  it('puts UDP traps in the log-only group', () => {
    const udp = trapGroups(reg).find((g) => g.id === 'udp')
    expect(udp?.note).toContain('never alerts')
    expect(udp?.traps.every((t) => t.transport === 'UDP')).toBe(true)
  })

  it('shows every plain setting except the ones handled elsewhere', () => {
    const shown = settingGroups(reg).flatMap((g) => g.settings.map((s) => s.name))
    expect(shown).not.toContain('RAN_CROWDSEC_PASSWORD')
    expect(shown).not.toContain('RAN_TRAPS')
    expect(shown).toContain('RAN_LOG_LEVEL')
    expect(shown).toContain('RAN_PROXY_TRUSTED')
  })

  it('offers per-trap fields', () => {
    expect(trapFields(reg, 'ssh').map((f) => f.key)).toContain('RAN_SSH_ADDR')
    expect(trapFields(reg, 'banner')[0].key).toBe('RAN_BANNER_SERVICES')
  })
})
