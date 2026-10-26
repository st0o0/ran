import { describe, expect, it } from 'vitest'
import settingsJson from '../../../data/settings.generated.json'
import casesJson from '../../../data/builder-cases.json'
import type { BuilderCase, BuilderState, Register } from './types'
import { effectiveEnv, setProxied, setValue } from './state'
import { applyScenario } from './scenarios'
import { outcomeOf, toIssues } from './checker'
import { nodeChecker } from './testing'

const reg = settingsJson as unknown as Register
const cases = (casesJson as unknown as { cases: BuilderCase[] }).cases
const checker = await nodeChecker()

function state(traps: string[], values: Record<string, string> = {}): BuilderState {
  return { traps, values, scenario: 'direct', proxied: [] }
}

describe('config check (the sensor config.Load as WebAssembly)', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(10)
  })

  // The Go suite replays the same vectors against config.Load directly; this
  // proves the browser build answers identically.
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
    let s = applyScenario(reg, state(['ssh', 'dns']), 'reverse-proxy')
    s = setProxied(s, 'dns', true)
    const issues = checker.check(effectiveEnv(s))
    expect(outcomeOf(issues)).toBe('error')
    expect(issues.some((i) => i.message.includes('UDP trap'))).toBe(true)
  })

  it('flags port conflicts', () => {
    const s = setValue(reg, state(['ssh', 'http']), 'RAN_HTTP_ADDR', ':2222')
    expect(outcomeOf(checker.check(effectiveEnv(s)))).toBe('error')
  })

  it('accepts every scenario with its defaults', () => {
    for (const id of ['direct', 'reverse-proxy', 'shared-namespace', 'crowdsec'] as const) {
      const s = applyScenario(reg, state(['ssh', 'http']), id)
      expect(outcomeOf(checker.check(effectiveEnv(s))), id).toBe('ok')
    }
  })
})
