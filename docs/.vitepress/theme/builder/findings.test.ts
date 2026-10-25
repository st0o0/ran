import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import type { BuilderState, Register } from './types'
import { defaultState, setProxied, setTrap, setValue } from './state'
import { evaluateEnv, outcomeOf } from './rules'
import { importEnv, portMappings, toCompose, toDockerRun, toEnvFile } from './serializer'
import { MAX_IGNORE_ENTRIES, parseIgnoreList } from './netaddr'
import { decodeShare, decodeState, encodeState } from './hash'
import { applyScenario } from './scenarios'

const reg = settingsJson as unknown as Register

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, scenario: 'direct', proxied: [] }
}
const issues = (env: Record<string, string>) => evaluateEnv(reg, { RAN_TRAPS: 'ssh', ...env })
const errors = (env: Record<string, string>) =>
  issues(env).filter((i) => i.level === 'error').map((i) => i.message)

describe('A: cooldown cap and shun without CrowdSec', () => {
  it('rejects cooldowns above 8760h', () => {
    expect(errors({ RAN_ALERT_COOLDOWN: '8761h' })).toEqual([
      'RAN_ALERT_COOLDOWN must not exceed 8760h, got "8761h"; use a value up to 8760h.'
    ])
    expect(errors({ RAN_REPEAT_COOLDOWN: '8760h1s' })[0]).toContain('must not exceed 8760h')
    expect(errors({ RAN_ALERT_COOLDOWN: '8760h' })).toEqual([])
    expect(errors({ RAN_REPEAT_COOLDOWN: '525600m' })).toEqual([])
  })
  it('warns when RAN_SHUN is on without CrowdSec', () => {
    const w = issues({ RAN_SHUN: 'on' })
    expect(w.map((i) => i.id)).toEqual(['shun-without-crowdsec'])
    expect(w[0].message).toContain('has no effect without RAN_CROWDSEC')
    const withCs = { RAN_CROWDSEC: 'on', RAN_CROWDSEC_URL: 'http://localhost:8080', RAN_CROWDSEC_MACHINE_ID: 'ran', RAN_SHUN: 'on' }
    expect(issues(withCs)).toEqual([])
  })
})

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

describe('F: validators', () => {
  it('bool values', () => {
    for (const v of ['on', 'ON', ' true ', 'yes', '1', 'off', 'False', 'no', '0'])
      expect(errors({ RAN_SHUN: v, RAN_CROWDSEC: 'off' }), v).toEqual([])
    for (const v of ['maybe', 'enabled', '2', 'y'])
      expect(errors({ RAN_SSH_TARPIT: v })[0], v).toContain('RAN_SSH_TARPIT must be on or off')
  })
  it('RAN_PROXY_PROTOCOL accepts the Go spellings', () => {
    for (const v of ['on', 'true', 'yes', '1']) {
      expect(errors({ RAN_PROXY_PROTOCOL: v, RAN_PROXY_TRUSTED: '127.0.0.1' }), v).toEqual([])
      expect(errors({ RAN_PROXY_PROTOCOL: v })[0], v).toContain('RAN_PROXY_TRUSTED is required')
    }
    for (const v of ['off', 'false', 'no', '0', ''])
      expect(errors({ RAN_PROXY_PROTOCOL: v }), v).toEqual([])
  })
  it('RAN_PROXY_TRUSTED', () => {
    const e = (t: string) => errors({ RAN_PROXY_PROTOCOL: 'on', RAN_PROXY_TRUSTED: t })
    for (const t of ['any', ' any ', '127.0.0.1,::1', '172.16.0.0/12', '2606:4700:4700::/48']) expect(e(t), t).toEqual([])
    for (const t of ['ANY', 'any,127.0.0.1', 'example.com', '10.0.0.0/33', 'proxy'])
      expect(e(t)[0], t).toContain('RAN_PROXY_TRUSTED has an invalid entry')
    expect(e('any,127.0.0.1')[0]).toContain('"any"')
    expect(e(' , ')[0]).toContain('RAN_PROXY_TRUSTED is required')
  })
  it('RAN_IGNORE_IPS accepts and rejects what ParseIgnoreList does', () => {
    const ok = ['', ' , ,, ', '8.8.8.8', '2606:4700:4700::1111', '1.1.1.0/24', '2606:4700:4700::/48', '1.1.1.77/24',
      '::ffff:8.8.8.8', '::ffff:1.1.1.0/120', '8.8.8.8,8.8.8.8, ::ffff:8.8.8.8 ,8.8.8.8/32', '::', '::1', '0.0.0.0/0', '::/0',
      '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:1.2.3.4', '::ffff:0:0/96']
    for (const v of ok) expect(errors({ RAN_IGNORE_IPS: v }), v).toEqual([])
    const bad = ['not-an-ip', '8.8.8.256', '8.8.8.0/33', '8.8.8.8/', '/24', 'fe80::1%eth0', 'fe80::1%eth0/64',
      '::ffff:1.1.1.0/64', 'example.com', '8.8.8.8;1.1.1.1', '1.1.1', '01.2.3.4', '1.1.1.0/024', '1.1.1.0/+24',
      '1:2:3:4:5:6:7:8:9', '1::2::3', ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7::8', '12345::']
    for (const v of bad) expect(errors({ RAN_IGNORE_IPS: '8.8.8.8, ' + v })[0], v).toContain('RAN_IGNORE_IPS has an invalid entry')
  })
  it('RAN_IGNORE_IPS entry limit counts distinct entries', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => `8.8.${Math.floor(i / 256)}.${i % 256}`).join(',')
    expect(parseIgnoreList(many(MAX_IGNORE_ENTRIES))).toEqual({ count: MAX_IGNORE_ENTRIES })
    expect(errors({ RAN_IGNORE_IPS: many(MAX_IGNORE_ENTRIES) + ',8.8.0.0,::ffff:8.8.0.1' })).toEqual([])
    expect(errors({ RAN_IGNORE_IPS: many(MAX_IGNORE_ENTRIES + 1) })[0]).toContain('more than 1024 distinct entries')
  })
  it('RAN_BAN_ON', () => {
    for (const v of ['attack', 'attack,scan', ' Probe , SCAN ', 'probe,,attack', 'scan,scan'])
      expect(errors({ RAN_BAN_ON: v }), v).toEqual([])
    expect(errors({ RAN_BAN_ON: 'attack,flood' })[0]).toContain('invalid class "flood"')
    expect(errors({ RAN_BAN_ON: ',' })[0]).toContain('at least one of probe, attack, scan')
    expect(errors({ RAN_BAN_ON: 'attack scan' })[0]).toContain('invalid class')
  })
  it('ints beyond 2^53 and int64', () => {
    expect(errors({ RAN_MAX_SESSIONS: '9223372036854775807' })).toEqual([])
    expect(errors({ RAN_MAX_SESSIONS: '9223372036854775808' })[0]).toContain('RAN_MAX_SESSIONS')
    expect(errors({ RAN_MAX_SESSIONS: '99999999999999999999999' })[0]).toContain('RAN_MAX_SESSIONS')
    expect(errors({ RAN_MAX_SESSIONS: '-9223372036854775809' })[0]).toContain('RAN_MAX_SESSIONS')
    expect(errors({ RAN_MAX_SESSIONS: '+5' })).toEqual([])
    expect(errors({ RAN_MAX_SESSIONS: '1_000' })[0]).toContain('whole number')
    // 2^53 + 1 is not representable as a double; the comparison must stay exact
    expect(errors({ RAN_UDP_RATE_PER_SOURCE: '9007199254740993', RAN_UDP_RATE_BURST: '9007199254740992', RAN_TRAPS: 'dns' }).join()).toContain('RAN_UDP_RATE_BURST')
  })
  it('an unknown trap and a UDP trap in a proxy list stay errors', () => {
    expect(outcomeOf(issues({ RAN_PROXY_PROTOCOL: 'dns', RAN_PROXY_TRUSTED: '127.0.0.1', RAN_TRAPS: 'ssh,dns' }))).toBe('error')
  })
})
