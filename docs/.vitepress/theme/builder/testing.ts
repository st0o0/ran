// Test helper: starts the compiled config check in Node. Needs docs/public/ran-config.wasm
// and wasm_exec.js, which `pnpm test` builds first (scripts/build-wasm.mjs).
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createChecker, type Checker, type GoRuntime } from './checker'

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'public')

export async function nodeChecker(): Promise<Checker> {
  // wasm_exec.js is a plain script that defines globalThis.Go
  ;(0, eval)(readFileSync(join(publicDir, 'wasm_exec.js'), 'utf8'))
  const Go = (globalThis as unknown as { Go: new () => GoRuntime }).Go
  return createChecker(new Go(), readFileSync(join(publicDir, 'ran-config.wasm')))
}
