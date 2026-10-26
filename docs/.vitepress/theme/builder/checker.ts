// The configuration check runs the real config.Load of the sensor, compiled to
// WebAssembly (internal/tools/configwasm, built by docs/scripts/build-wasm.mjs).
// This module only loads it and maps the answer to the builder's issue list.
import { PASSWORD_PLACEHOLDER, SECRET_KEYS, type Issue } from './types'

/** Subset of the Go runtime glue (wasm_exec.js) used here. */
export interface GoRuntime {
  importObject: WebAssembly.Imports
  run(instance: WebAssembly.Instance): Promise<void>
}

export interface Diagnosis {
  error: string
  warnings: string[]
}

export interface Checker {
  /** Checks a flat environment (variables that differ from the default). */
  check(env: Record<string, string>): Issue[]
}

type CheckFn = (envJson: string) => string

/** Maps the Go answer to issues. Load stops at the first error, so there is at most one. */
export function toIssues(d: Diagnosis): Issue[] {
  if (d.error !== '') return [{ id: 'load-error', level: 'error', message: d.error }]
  return d.warnings.map((message, i) => ({ id: `warning-${i}`, level: 'warning' as const, message }))
}

/** Starts the Go program in `wasm` and returns the checker it registers. */
export async function createChecker(go: GoRuntime, wasm: BufferSource): Promise<Checker> {
  const { instance } = await WebAssembly.instantiate(wasm, go.importObject)
  void go.run(instance)
  // main registers ranCheck before it blocks, so it exists once run() has returned control.
  const fn = (globalThis as unknown as { ranCheck?: CheckFn }).ranCheck
  if (typeof fn !== 'function') throw new Error('the config check did not start')
  return {
    check(env) {
      // The builder never holds secrets; Load needs them, so check with the placeholder.
      const withSecrets = { ...Object.fromEntries(SECRET_KEYS.map((k) => [k, PASSWORD_PLACEHOLDER])), ...env }
      return toIssues(JSON.parse(fn(JSON.stringify(withSecrets))) as Diagnosis)
    }
  }
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script')
    s.src = src
    s.onload = () => resolve()
    s.onerror = () => reject(new Error(`could not load ${src}`))
    document.head.appendChild(s)
  })
}

/** Browser loader: `base` is the site base ("/ran/"). */
export async function loadChecker(base: string): Promise<Checker> {
  await loadScript(`${base}wasm_exec.js`)
  const Go = (globalThis as unknown as { Go?: new () => GoRuntime }).Go
  if (!Go) throw new Error('the Go runtime glue did not load')
  const res = await fetch(`${base}ran-config.wasm`)
  if (!res.ok) throw new Error(`could not load the config check (${res.status})`)
  return createChecker(new Go(), await res.arrayBuffer())
}

export type Outcome = 'ok' | 'warning' | 'error'

export function outcomeOf(issues: Issue[]): Outcome {
  if (issues.some((i) => i.level === 'error')) return 'error'
  if (issues.some((i) => i.level === 'warning')) return 'warning'
  return 'ok'
}
