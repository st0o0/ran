import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import type { BuilderState, Register } from './types'
import { defaultState, setProxied, setTrap, setValue } from './state'
import { importEnv, portMappings, toCompose, toDockerRun, toEnvFile } from './serializer'
import { decodeShare, decodeState, encodeState } from './hash'
import { applyScenario } from './scenarios'

const reg = settingsJson as unknown as Register

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, scenario: 'direct', proxied: [] }
}
describe('B: proxied traps are not published', () => {
  const rp = () => applyScenario(reg, state(['ssh', 'http', 'https']), 'reverse-proxy')
  it('omits the proxied ports and explains how the proxy reaches ran', () => {
    const s = setProxied(rp(), 'https', false)
    expect(portMappings(reg, s).map((p) => p.spec)).toEqual(['2222:2222', '8443:8443', '127.0.0.1:9550:9550'])
    const c = toCompose(reg, s).text
    expect(c).not.toContain('"8081:8081"')
    expect(c).toContain('"8443:8443"')
    expect(c).toMatch(/# .*ran:8081/)
    const r = toDockerRun(reg, s).text
    expect(r).not.toContain('-p 8081:8081')
    expect(r).toMatch(/^# .*ran:8081/m)
  })
  it('shared namespace points at loopback', () => {
    const s = applyScenario(reg, state(['http']), 'shared-namespace')
    const c = toCompose(reg, s).text
    expect(c).not.toContain('8081:8081')
    expect(c).toMatch(/# .*127\.0\.0\.1:8081/)
  })
  it('keeps direct output free of proxy comments', () => {
    expect(toCompose(reg, state(['http'])).text).not.toContain('Proxied')
    expect(toCompose(reg, state(['http'])).text).toContain('"8081:8081"')
  })
})

describe('C: CrowdSec comments', () => {
  const s = applyScenario(reg, state(['ssh']), 'crowdsec')
  for (const [name, text] of [['compose', toCompose(reg, s).text], ['docker run', toDockerRun(reg, s).text]]) {
    it(`${name} explains LAPI reachability`, () => {
      expect(text).toContain('http://crowdsec:8080')
      expect(text).toMatch(/# .*first failed (LAPI )?login is fatal/)
      expect(text).toContain('CHANGE_ME')
    })
  }
  it('docker run mentions --network', () => {
    expect(toDockerRun(reg, s).text).toContain('--network <name>')
  })
  it('stays quiet without CrowdSec', () => {
    expect(toCompose(reg, state(['ssh'])).text).not.toContain('LAPI')
  })
})

describe('D: escaping', () => {
  const s = state(['banner'], { RAN_BANNER_SERVICES: '2222=ssh:SSH-2.0-a$b c #d', RAN_CATCHALL_ADDR: ':1' })
  it('doubles $ in compose environment values', () => {
    expect(toCompose(reg, s).text).toContain('"2222=ssh:SSH-2.0-a$$b c #d"')
  })
  it('quotes env file values', () => {
    const t = toEnvFile(reg, s).text
    expect(t).toContain("RAN_BANNER_SERVICES='2222=ssh:SSH-2.0-a$b c #d'\n")
    expect(t).toContain('RAN_CATCHALL_ADDR=:1\n')
  })
  it('uses double quotes with escapes when a value has a single quote', () => {
    const q = state(['banner'], { RAN_BANNER_SERVICES: `2222=x:it's $HOME "q" \\` })
    const t = toEnvFile(reg, q).text
    expect(t).toContain('RAN_BANNER_SERVICES="2222=x:it\'s \\$HOME \\"q\\" \\\\"\n')
    expect(importEnv(reg, t).state.values.RAN_BANNER_SERVICES).toBe(`2222=x:it's $HOME "q" \\`)
  })
  it('round trips quoted values', () => {
    const back = importEnv(reg, toEnvFile(reg, s).text)
    expect(back.state.values.RAN_BANNER_SERVICES).toBe('2222=ssh:SSH-2.0-a$b c #d')
  })
  it('strips line separators and control characters', () => {
    const v = setValue(reg, state(['banner']), 'RAN_BANNER_SERVICES', 'a b\u0085c\u0000d\te f\r\ng')
    expect(v.values.RAN_BANNER_SERVICES).toBe('a b c d e f g')
  })
})

describe('E: share link', () => {
  const enc = (o: unknown) => encodeJson(o)
  function encodeJson(o: unknown): string {
    // reuse the real encoder through a state is not possible for junk, so build the hash by hand
    const bytes = new TextEncoder().encode(JSON.stringify(o))
    let bin = ''
    for (const b of bytes) bin += String.fromCharCode(b)
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  it('drops unknown keys and traps and sanitizes values', () => {
    const r = decodeShare(enc({ t: ['ssh', 'nope'], v: { RAN_NOPE: '1', RAN_LOG_LEVEL: 'debug x', RAN_MAX_PER_IP: '10' }, p: ['bogus'] }), reg)
    expect(r.problem).toBeNull()
    expect(r.state.traps).toEqual(['ssh'])
    expect(r.state.values).toEqual({ RAN_LOG_LEVEL: 'debug x' })
    expect(r.state.proxied).toEqual([])
    expect(r.dropped).toEqual(expect.arrayContaining(['nope', 'RAN_NOPE', 'bogus']))
  })
  it('reports a reason for invalid or oversized links', () => {
    expect(decodeShare('!!!', reg).problem).toBe('invalid')
    expect(decodeShare(enc({ t: ['ssh'], v: { RAN_LOG_LEVEL: 'x'.repeat(20000) } }), reg).problem).toBe('too-large')
    expect(decodeShare('', reg).problem).toBeNull()
  })
  it('round trips all 40 traps with typical overrides', () => {
    let s = state(reg.traps.map((t) => t.name))
    for (const t of reg.traps) {
      if (t.addressless) continue
      const p = t.name.toUpperCase()
      s = setValue(reg, s, `RAN_${p}_ADDR`, '0.0.0.0:41000,[::]:41001')
      s = setValue(reg, s, `RAN_${p}_SESSION_TIMEOUT`, '17s')
      s = setValue(reg, s, `RAN_${p}_AUTH_DELAY`, '321ms')
      s = setValue(reg, s, `RAN_${p}_MAX_AUTH_RETRIES`, '7')
    }
    s = setValue(reg, s, 'RAN_BANNER_SERVICES', Array.from({ length: 10 }, (_, i) => `${2000 + i}=svc${i}:${'B'.repeat(200)}`).join(','))
    s = setValue(reg, s, 'RAN_CATCHALL_ADDR', ':1000,:1001')
    s = setValue(reg, s, 'RAN_IGNORE_IPS', Array.from({ length: 200 }, (_, i) => `8.8.${i}.0/24`).join(','))
    const r = decodeShare(encodeState(s), reg)
    expect(r.problem).toBeNull()
    expect(r.state).toEqual(s)
    expect(decodeState(encodeState(s), reg)).toEqual(s)
  })
  it('does not lose password-free state on a normal round trip', () => {
    let s = setTrap(defaultState(), 'dns', true)
    s = setValue(reg, s, 'RAN_LOG_LEVEL', 'debug')
    expect(decodeState(encodeState(s), reg)).toEqual(s)
  })
})

