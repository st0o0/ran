import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import type { BuilderState, Register } from './types'
import { cloneState, defaultState, effectiveEnv, sameState, setProxied, setTrap, setValue } from './state'
import { hints } from './hints'
import { outcomeOf } from './checker'
import { nodeChecker } from './testing'
import { exportEnv, importEnv, portMappings, serialize, shellQuote, toCompose, toDockerRun, toEnvFile } from './serializer'
import { base64UrlToBytes, bytesToBase64Url, decodeState, encodeState } from './hash'

const reg = settingsJson as unknown as Register
const checker = await nodeChecker()

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, proxied: [] }
}

describe('delta export', () => {
  it('omits values equal to the default', () => {
    let s = state(['ssh'])
    s = setValue(reg, s, 'RAN_LOG_LEVEL', 'info') // default
    s = setValue(reg, s, 'RAN_MAX_PER_IP', '10') // default
    s = setValue(reg, s, 'RAN_SSH_ADDR', ':2222') // trap default
    expect(toEnvFile(reg, s).text).toBe('RAN_TRAPS=ssh\n')
  })

  it('writes changed values in a stable order', () => {
    let s = state(['ssh', 'http'])
    s = setValue(reg, s, 'RAN_MAX_SESSIONS', '100')
    s = setValue(reg, s, 'RAN_LOG_LEVEL', 'debug')
    s = setValue(reg, s, 'RAN_HTTP_ADDR', ':8088')
    const a = toEnvFile(reg, s).text
    expect(a).toBe('RAN_TRAPS=ssh,http\nRAN_HTTP_ADDR=:8088\nRAN_MAX_SESSIONS=100\nRAN_LOG_LEVEL=debug\n')
    expect(toEnvFile(reg, cloneState(s)).text).toBe(a)
  })

  it('removes the entry when set back to the default', () => {
    let s = setValue(reg, state(['ssh']), 'RAN_LOG_LEVEL', 'debug')
    expect(s.values.RAN_LOG_LEVEL).toBe('debug')
    s = setValue(reg, s, 'RAN_LOG_LEVEL', 'info')
    expect(s.values).toEqual({})
  })
})

describe('output formats', () => {
  const s = setValue(reg, state(['ssh', 'dns', 'telnet']), 'RAN_LOG_LEVEL', 'debug')

  it('derives compose ports from traps and transports', () => {
    const out = toCompose(reg, s).text
    expect(out).toContain('image: ghcr.io/st0o0/ran:latest')
    expect(out).toContain('cap_drop: [ALL]')
    expect(out).toContain('read_only: true')
    expect(out).toContain('ran-data:/data')
    expect(out).toContain('RAN_LOG_LEVEL: "debug"')
    expect(out).toContain('"2222:2222"')
    expect(out).toContain('"53:53/udp"')
    expect(out).toContain('"23:23"')
    expect(out).toContain('"2323:2323"')
    expect(out).toContain('"127.0.0.1:9550:9550"')
    expect(out).not.toContain('"53:53"')
  })

  it('uses a custom listen address for the port', () => {
    const m = portMappings(reg, setValue(reg, state(['http']), 'RAN_HTTP_ADDR', '0.0.0.0:9000,[::]:9001'))
    expect(m.map((p) => p.spec)).toEqual(['9000:9000', '9001:9001', '127.0.0.1:9550:9550'])
  })

  it('writes a docker run line', () => {
    const out = toDockerRun(reg, s).text
    expect(out.startsWith('docker run -d --name ran')).toBe(true)
    expect(out).toContain('-e RAN_TRAPS=ssh,dns,telnet')
    expect(out).toContain('-p 53:53/udp')
    expect(out.trimEnd().endsWith('ghcr.io/st0o0/ran:latest')).toBe(true)
  })

  it('quotes shell values', () => {
    expect(shellQuote('a b')).toBe("'a b'")
    expect(shellQuote("it's")).toBe("'it'\\''s'")
    expect(shellQuote('RAN_X=1')).toBe('RAN_X=1')
  })

  it('dispatches by format', () => {
    expect(serialize(reg, s, 'env').text).toBe(toEnvFile(reg, s).text)
    expect(serialize(reg, s, 'compose').text).toBe(toCompose(reg, s).text)
    expect(serialize(reg, s, 'run').text).toBe(toDockerRun(reg, s).text)
  })
})

describe('env import', () => {
  it('skips comments and blank lines and reports unknown keys', () => {
    const r = importEnv(reg, '# comment\n\nRAN_TRAPS=ssh,http\nexport RAN_LOG_LEVEL="debug"\nFOO=bar\nRAN_NOPE=1\r\n')
    expect(r.state.traps).toEqual(['ssh', 'http'])
    expect(r.state.values).toEqual({ RAN_LOG_LEVEL: 'debug' })
    expect(r.unknown).toEqual(['FOO', 'RAN_NOPE'])
  })

  it('round trips exports', () => {
    let a = setValue(reg, state(['ssh', 'dns']), 'RAN_SESSION_TIMEOUT', '45s')
    a = setValue(reg, a, 'RAN_SSH_SESSION_TIMEOUT', '10s')

    // proxy config
    let b = state(['ssh', 'http'])
    b = setProxied(b, 'http', true)
    b = setValue(reg, b, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')

    // crowdsec config
    let c = state(['ssh'])
    c = setValue(reg, c, 'RAN_CROWDSEC', 'on')
    c = setValue(reg, c, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    c = setValue(reg, c, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')

    for (const s of [a, b, c]) {
      const text = toEnvFile(reg, s).text
      const back = importEnv(reg, text)
      expect(back.unknown).toEqual([])
      expect(toEnvFile(reg, back.state).text).toBe(text)
    }

    // shared namespace
    let d = state(['http'])
    d = setProxied(d, 'http', true)
    d = setValue(reg, d, 'RAN_PROXY_TRUSTED', '127.0.0.1,::1')
    expect(importEnv(reg, toEnvFile(reg, d).text).state.proxied).toEqual(['http'])

    expect(sameState(importEnv(reg, toEnvFile(reg, c).text).state, c)).toBe(true)
  })

  it('never keeps a password from an imported file', () => {
    const r = importEnv(reg, 'RAN_TRAPS=ssh\nRAN_CROWDSEC=on\nRAN_CROWDSEC_PASSWORD=hunter2\n')
    expect(r.ignored).toEqual(['RAN_CROWDSEC_PASSWORD'])
    expect(JSON.stringify(r.state)).not.toContain('hunter2')
  })
})

describe('hash', () => {
  it('round trips a state', () => {
    let s = state(['ssh', 'http'])
    s = setProxied(s, 'http', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    s = setValue(reg, s, 'RAN_LOG_LEVEL', 'debug')
    s = setTrap(s, 'dns', true)
    expect(decodeState(encodeState(s), reg)).toEqual(s)
    expect(decodeState('#' + encodeState(s), reg)).toEqual(s)
  })

  it('round trips non-Latin-1 input', () => {
    const s = setValue(reg, state(['banner']), 'RAN_BANNER_SERVICES', '2222=ssh:SSH-2.0-Über € 中文 🚀')
    const hash = encodeState(s)
    expect(/^[A-Za-z0-9_-]*$/.test(hash)).toBe(true)
    expect(decodeState(hash, reg)).toEqual(s)
  })

  it('falls back to defaults for broken input without throwing', () => {
    const bad = [
      '',
      '!!!',
      'a',
      'AAAA',
      'e30', // {}
      bytesToBase64Url(new TextEncoder().encode('not json')),
      bytesToBase64Url(new TextEncoder().encode('[1,2]')),
      bytesToBase64Url(new TextEncoder().encode('{"t":[1]}')),
      bytesToBase64Url(new TextEncoder().encode('{"t":["ssh"],"v":{"lower":"x"}}')),
      bytesToBase64Url(Uint8Array.from([0xff, 0xfe, 0xfd]))
    ]
    for (const h of bad) {
      expect(() => decodeState(h, reg)).not.toThrow()
    }
    for (const h of bad.filter((x) => x !== 'e30')) {
      expect(decodeState(h, reg)).toEqual(defaultState())
    }
  })

  it('gracefully ignores legacy scenario field', () => {
    const legacy = bytesToBase64Url(new TextEncoder().encode('{"t":["ssh"],"s":"crowdsec"}'))
    const s = decodeState(legacy, reg)
    expect(s.traps).toEqual(['ssh'])
  })

  it('does not carry a password', () => {
    const s = state(['ssh'], { RAN_CROWDSEC: 'on', RAN_CROWDSEC_PASSWORD: 'hunter2' })
    const text = new TextDecoder().decode(base64UrlToBytes(encodeState(s)) as Uint8Array)
    expect(text).not.toContain('hunter2')
  })
})

describe('hints', () => {
  it('hints about UDP, wide port sets and trusting any peer', () => {
    const udp = hints(reg, state(['dns']))
    expect(udp.map((h) => h.id)).toContain('udp-log-only')
    const ports = Array.from({ length: 25 }, (_, i) => `:${3000 + i}`).join(',')
    const wide = hints(reg, setValue(reg, state(['catchall']), 'RAN_CATCHALL_ADDR', ports))
    expect(wide.map((h) => h.id)).toEqual(expect.arrayContaining(['wide-port-set', 'catchall-volume']))
    const any = hints(reg, state(['ssh'], { RAN_PROXY_TRUSTED: 'any' }))
    expect(any.map((h) => h.id)).toContain('trusted-any')
  })
})

describe('proxy', () => {
  it('proxy config sets the chosen traps and trusted ranges', () => {
    let s = state(['ssh', 'http', 'vnc'])
    s = setProxied(s, 'http', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    const text = toEnvFile(reg, s).text
    expect(text).toContain('RAN_PROXY_PROTOCOL=http\n')
    expect(text).toContain('RAN_PROXY_TRUSTED=')
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('ok')
    const h = hints(reg, s)
    const caddy = h.find((x) => x.id === 'caddy-http')
    expect(caddy?.code).toContain('proxy_protocol v2')
    expect(caddy?.code).toContain('reverse_proxy ran:8081')
  })

  it('proxy follows the picked traps', () => {
    let s = state(['ssh', 'http', 'https'])
    s = setProxied(s, 'http', true)
    s = setProxied(s, 'https', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    expect(s.proxied).toEqual(['http', 'https'])
    s = setProxied(s, 'https', false)
    expect(toEnvFile(reg, s).text).toContain('RAN_PROXY_PROTOCOL=http\n')
    s = setTrap(s, 'http', false)
    expect(s.proxied).toEqual([])
  })

  it('shared namespace trusts loopback', () => {
    let s = state(['http'])
    s = setProxied(s, 'http', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '127.0.0.1,::1')
    expect(toEnvFile(reg, s).text).toContain('RAN_PROXY_TRUSTED=127.0.0.1,::1\n')
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('ok')
  })

  it('no proxy has no proxy settings', () => {
    const s = state(['ssh', 'http'])
    const env = effectiveEnv(s)
    expect(env.RAN_PROXY_PROTOCOL).toBeUndefined()
  })
})

describe('crowdsec', () => {
  it('writes CHANGE_ME and a visible note, never a real password', () => {
    let s = state(['ssh'])
    s = setValue(reg, s, 'RAN_CROWDSEC', 'on')
    s = setValue(reg, s, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    s = setValue(reg, s, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')
    s = { ...s, values: { ...s.values, RAN_CROWDSEC_PASSWORD: 'hunter2' } }
    const env = toEnvFile(reg, s)
    expect(env.text).toContain('RAN_CROWDSEC=on\n')
    expect(env.text).toContain('RAN_CROWDSEC_URL=http://crowdsec:8080\n')
    expect(env.text).toContain('RAN_CROWDSEC_MACHINE_ID=ran-honeypot\n')
    expect(env.text).toContain('RAN_CROWDSEC_PASSWORD=CHANGE_ME\n')
    expect(env.text).not.toContain('hunter2')
    expect(env.notes.join(' ')).toContain('CHANGE_ME')
    expect(toCompose(reg, s).text).toContain('RAN_CROWDSEC_PASSWORD: "CHANGE_ME"')
    expect(toDockerRun(reg, s).text).toContain('RAN_CROWDSEC_PASSWORD=CHANGE_ME')
    expect(exportEnv(reg, state(['ssh'])).notes).toEqual([])
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('ok')
    expect(hints(reg, s).some((h) => h.id.startsWith('crowdsec-'))).toBe(true)
  })
})

describe('combined proxy + crowdsec', () => {
  it('accepts proxy and crowdsec together', () => {
    let s = state(['ssh', 'http'])
    s = setProxied(s, 'http', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '127.0.0.1,::1')
    s = setValue(reg, s, 'RAN_CROWDSEC', 'on')
    s = setValue(reg, s, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    s = setValue(reg, s, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('ok')
    const text = toEnvFile(reg, s).text
    expect(text).toContain('RAN_PROXY_PROTOCOL=http\n')
    expect(text).toContain('RAN_CROWDSEC=on\n')
  })
})
