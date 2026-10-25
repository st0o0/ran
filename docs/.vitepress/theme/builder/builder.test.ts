import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import casesJson from '../../../data/builder-cases.json'
import type { BuilderCase, BuilderState, Register } from './types'
import { cloneState, defaultState, effectiveEnv, sameState, setProxied, setTrap, setValue } from './state'
import { checkCase, durationMs, evaluate, evaluateEnv, hints, outcomeOf } from './rules'
import { exportEnv, importEnv, portMappings, serialize, shellQuote, toCompose, toDockerRun, toEnvFile } from './serializer'
import { base64UrlToBytes, bytesToBase64Url, decodeState, encodeState } from './hash'
import { applyScenario, scenarioHints } from './scenarios'

const reg = settingsJson as unknown as Register
const cases = (casesJson as unknown as { cases: BuilderCase[] }).cases

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, scenario: 'direct', proxied: [] }
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

  it('round trips exports of every shape', () => {
    let a = setValue(reg, state(['ssh', 'dns']), 'RAN_SESSION_TIMEOUT', '45s')
    a = setValue(reg, a, 'RAN_SSH_SESSION_TIMEOUT', '10s')
    let b = applyScenario(reg, defaultState(), 'reverse-proxy')
    let c = applyScenario(reg, defaultState(), 'crowdsec')
    for (const s of [a, b, c]) {
      const text = toEnvFile(reg, s).text
      const back = importEnv(reg, text)
      expect(back.unknown).toEqual([])
      expect(toEnvFile(reg, back.state).text).toBe(text)
    }
    b = applyScenario(reg, defaultState(), 'shared-namespace')
    expect(importEnv(reg, toEnvFile(reg, b).text).state.scenario).toBe('shared-namespace')
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
    let s = applyScenario(reg, defaultState(), 'reverse-proxy')
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
      bytesToBase64Url(new TextEncoder().encode('{"t":["ssh"],"s":"nope"}')),
      bytesToBase64Url(Uint8Array.from([0xff, 0xfe, 0xfd]))
    ]
    for (const h of bad) {
      expect(() => decodeState(h, reg)).not.toThrow()
    }
    for (const h of bad.filter((x) => x !== 'e30')) {
      expect(decodeState(h, reg)).toEqual(defaultState())
    }
  })

  it('does not carry a password', () => {
    const s = state(['ssh'], { RAN_CROWDSEC: 'on', RAN_CROWDSEC_PASSWORD: 'hunter2' })
    const text = new TextDecoder().decode(base64UrlToBytes(encodeState(s)) as Uint8Array)
    expect(text).not.toContain('hunter2')
  })
})

describe('rules replay builder-cases.json', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(10)
  })
  for (const c of cases) {
    it(c.id, () => {
      expect(checkCase(reg, c)).toBeNull()
    })
  }
})

describe('rules on builder state', () => {
  it('flags a UDP trap in the PROXY list', () => {
    let s = applyScenario(reg, state(['ssh', 'dns']), 'reverse-proxy')
    s = setProxied(s, 'dns', true)
    const issues = evaluate(reg, s)
    expect(outcomeOf(issues)).toBe('error')
    expect(issues.some((i) => i.message.includes('UDP trap'))).toBe(true)
  })

  it('flags port conflicts', () => {
    const s = setValue(reg, state(['ssh', 'http']), 'RAN_HTTP_ADDR', ':2222')
    expect(outcomeOf(evaluate(reg, s))).toBe('error')
  })

  it('validates value formats', () => {
    expect(outcomeOf(evaluateEnv(reg, { RAN_TRAPS: 'ssh', RAN_SESSION_TIMEOUT: 'soon' }))).toBe('error')
    expect(outcomeOf(evaluateEnv(reg, { RAN_TRAPS: 'ssh', RAN_MAX_PER_IP: '-1' }))).toBe('error')
    expect(outcomeOf(evaluateEnv(reg, { RAN_TRAPS: 'ssh', RAN_SSH_ADDR: '2222' }))).toBe('error')
  })

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

describe('scenarios', () => {
  it('direct has no proxy settings', () => {
    const s = applyScenario(reg, applyScenario(reg, defaultState(), 'reverse-proxy'), 'direct')
    const env = effectiveEnv(s)
    expect(env.RAN_PROXY_PROTOCOL).toBeUndefined()
    expect(env.RAN_PROXY_TRUSTED).toBeUndefined()
  })

  it('reverse proxy sets the chosen traps, trusted ranges and a Caddy hint', () => {
    const s = applyScenario(reg, state(['ssh', 'vnc']), 'reverse-proxy')
    expect(s.traps).toContain('http')
    const text = toEnvFile(reg, s).text
    expect(text).toContain('RAN_PROXY_PROTOCOL=http\n')
    expect(text).toContain('RAN_PROXY_TRUSTED=')
    expect(outcomeOf(evaluate(reg, s))).toBe('ok')
    const h = scenarioHints(reg, s)
    const caddy = h.find((x) => x.id === 'caddy-http')
    expect(caddy?.code).toContain('proxy_protocol v2')
    expect(caddy?.code).toContain('reverse_proxy ran:8081')
  })

  it('reverse proxy follows the picked traps', () => {
    let s = applyScenario(reg, state(['ssh', 'http', 'https']), 'reverse-proxy')
    expect(s.proxied).toEqual(['http', 'https'])
    s = setProxied(s, 'https', false)
    expect(toEnvFile(reg, s).text).toContain('RAN_PROXY_PROTOCOL=http\n')
    s = setTrap(s, 'http', false)
    expect(s.proxied).toEqual([])
  })

  it('shared namespace trusts loopback', () => {
    const s = applyScenario(reg, state(['http']), 'shared-namespace')
    expect(toEnvFile(reg, s).text).toContain('RAN_PROXY_TRUSTED=127.0.0.1,::1\n')
    expect(outcomeOf(evaluate(reg, s))).toBe('ok')
  })

  it('crowdsec writes CHANGE_ME and a visible note, never a real password', () => {
    let s = applyScenario(reg, state(['ssh']), 'crowdsec')
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
    expect(outcomeOf(evaluate(reg, s))).toBe('ok')
    expect(scenarioHints(reg, s).length).toBeGreaterThan(0)
  })
})

describe('value rules follow the register and Go', () => {
  const messages = (env: Record<string, string>) =>
    evaluateEnv(reg, { RAN_TRAPS: 'ssh', ...env }).map((i) => i.message)

  it('enforces the int minimum from the register', () => {
    expect(messages({ RAN_MAX_SESSIONS: '0' })).toContain('RAN_MAX_SESSIONS must be a whole number >= 1, got "0".')
    expect(messages({ RAN_REPEAT_AFTER: '0' })).toContain('RAN_REPEAT_AFTER must be a whole number >= 1, got "0".')
    expect(messages({ RAN_MAX_AUTH_RETRIES: '0' })).toEqual([])
    expect(messages({ RAN_MAX_AUTH_RETRIES: '-1' })).toContain('RAN_MAX_AUTH_RETRIES must be a whole number >= 0, got "-1".')
    expect(messages({ RAN_SSH_MAX_AUTH_RETRIES: '-1' })).toHaveLength(1)
    expect(messages({ RAN_MAX_SESSIONS: '1' })).toEqual([])
  })

  it('every int setting declares a min', () => {
    for (const s of reg.settings.filter((x) => x.kind === 'int')) expect(s.min, s.name).toBeTypeOf('number')
  })

  it('accepts durations like time.ParseDuration', () => {
    for (const v of ['0', '30s', '1h30m', '1.5h', '.5s', '10us', '10' + String.fromCharCode(0xb5) + 's', '10' + String.fromCharCode(0x3bc) + 's', '5ns', '+5s']) {
      expect(durationMs(v), v).not.toBeNull()
      expect(messages({ RAN_AUTH_DELAY: v }), v).toEqual([])
    }
    for (const v of ['-5s', '5', 's', '5x', '1h 30m', '1,5s']) {
      expect(durationMs(v), v).toBeNull()
      expect(messages({ RAN_AUTH_DELAY: v }), v).toHaveLength(1)
    }
    expect(durationMs('1h30m')).toBe(5400000)
  })

  it('requires positive durations where Load does', () => {
    expect(messages({ RAN_REPEAT_COOLDOWN: '0s' })).toContain('RAN_REPEAT_COOLDOWN must be greater than zero, got "0s".')
    expect(messages({ RAN_SESSION_TIMEOUT: '0' })).toHaveLength(1)
    expect(messages({ RAN_SSH_SESSION_TIMEOUT: '0s' })).toHaveLength(1)
    expect(messages({ RAN_AUTH_DELAY: '0s' })).toEqual([])
  })

  it('warns about cooldown settings that do nothing', () => {
    const ids = (env: Record<string, string>) =>
      evaluateEnv(reg, { RAN_TRAPS: 'ssh', ...env }).map((i) => i.id)
    const cs = { RAN_CROWDSEC: 'on', RAN_CROWDSEC_URL: 'http://localhost:8080', RAN_CROWDSEC_MACHINE_ID: 'ran' }
    expect(ids({ ...cs, RAN_SHUN: 'on', RAN_ALERT_COOLDOWN: '0s' })).toEqual(['shun-without-cooldown'])
    expect(ids({ RAN_SHUN: 'on', RAN_ALERT_COOLDOWN: '0s' })).toEqual(['shun-without-cooldown', 'shun-without-crowdsec'])
    expect(ids({ RAN_REPEAT_COOLDOWN: '12h', RAN_ALERT_COOLDOWN: '0' })).toEqual(['repeat-without-cooldown'])
    expect(ids({ RAN_REPEAT_COOLDOWN: '30m' })).toEqual(['repeat-below-cooldown'])
    expect(ids({ RAN_REPEAT_COOLDOWN: '1h' })).toEqual([])
    expect(ids({ ...cs, RAN_SHUN: 'on' })).toEqual([])
  })
})
