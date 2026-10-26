import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import casesJson from '../../../data/builder-cases.json'
import type { BuilderCase, BuilderState, Register } from './types'
import { effectiveEnv, setProxied, setValue } from './state'
import { outcomeOf, toIssues } from './checker'
import { nodeChecker } from './testing'

const reg = settingsJson as unknown as Register
const cases = (casesJson as unknown as { cases: BuilderCase[] }).cases
const checker = await nodeChecker()

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, proxied: [] }
}

describe('config check (the sensor config.Load as WebAssembly)', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(10)
  })

  for (const c of cases) {
    it(c.id, () => {
      const issues = checker.check(c.env)
      expect(outcomeOf(issues)).toBe(c.expect)
      if (c.message_contains) {
        expect(issues.some((i) => i.level === c.expect && i.message.includes(c.message_contains!))).toBe(true)
      }
    })
  }

  it('reports the first error only, with the variable name', () => {
    const issues = checker.check({ RAN_TRAPS: 'ssh', RAN_SESSION_TIMEOUT: 'soon' })
    expect(issues).toHaveLength(1)
    expect(issues[0].message).toContain('RAN_SESSION_TIMEOUT')
  })

  it('ignores RAN_HTTP_FIXTURES, a path the browser cannot read', () => {
    expect(checker.check({ RAN_TRAPS: 'http', RAN_HTTP_FIXTURES: '/fixtures.json' })).toEqual([])
  })

  it('maps a diagnosis to issues', () => {
    expect(toIssues({ error: '', warnings: [] })).toEqual([])
    expect(toIssues({ error: 'boom', warnings: ['x'] }).map((i) => i.level)).toEqual(['error'])
    expect(toIssues({ error: '', warnings: ['a', 'b'] }).map((i) => i.id)).toEqual(['warning-0', 'warning-1'])
  })
})

describe('builder states', () => {
  it('flags a UDP trap in the PROXY list', () => {
    let s = state(['ssh', 'dns'])
    s = setProxied(s, 'dns', true)
    s = setValue(reg, s, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    const issues = checker.check(effectiveEnv(s))
    expect(outcomeOf(issues)).toBe('error')
    expect(issues.some((i) => i.message.includes('UDP trap'))).toBe(true)
  })

  it('flags port conflicts', () => {
    const s = setValue(reg, state(['ssh', 'http']), 'RAN_HTTP_ADDR', ':2222')
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('error')
  })

  it('accepts proxy, crowdsec and combined configurations', () => {
    // direct
    expect(outcomeOf(checker.check(effectiveEnv(state(['ssh', 'http']))))).toBe('ok')

    // proxy
    let rp = state(['ssh', 'http'])
    rp = setProxied(rp, 'http', true)
    rp = setValue(reg, rp, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    expect(outcomeOf(checker.check(effectiveEnv(rp)))).toBe('ok')

    // shared namespace
    let sn = state(['http'])
    sn = setProxied(sn, 'http', true)
    sn = setValue(reg, sn, 'RAN_PROXY_TRUSTED', '127.0.0.1,::1')
    expect(outcomeOf(checker.check(effectiveEnv(sn)))).toBe('ok')

    // crowdsec
    let cs = state(['ssh'])
    cs = setValue(reg, cs, 'RAN_CROWDSEC', 'on')
    cs = setValue(reg, cs, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    cs = setValue(reg, cs, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')
    expect(outcomeOf(checker.check(effectiveEnv(cs)))).toBe('ok')

    // proxy + crowdsec combined
    let combined = state(['ssh', 'http'])
    combined = setProxied(combined, 'http', true)
    combined = setValue(reg, combined, 'RAN_PROXY_TRUSTED', '127.0.0.1,::1')
    combined = setValue(reg, combined, 'RAN_CROWDSEC', 'on')
    combined = setValue(reg, combined, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    combined = setValue(reg, combined, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')
    expect(outcomeOf(checker.check(effectiveEnv(combined)))).toBe('ok')
  })
})
