// Builds the WebAssembly config check the builder page loads (see
// internal/tools/configwasm) and copies the matching Go runtime glue next to it.
// Needs a Go toolchain; go.mod pins the version and Go downloads it on demand.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', '..')
const out = resolve(here, '..', 'public')
mkdirSync(out, { recursive: true })

const run = (args, env = {}) =>
  execFileSync('go', args, { cwd: root, env: { ...process.env, ...env }, encoding: 'utf8' }).trim()

run(
  ['build', '-trimpath', '-ldflags=-s -w', '-o', join(out, 'ran-config.wasm'), './internal/tools/configwasm'],
  { GOOS: 'js', GOARCH: 'wasm' }
)

const goroot = run(['env', 'GOROOT'])
const glue = [join(goroot, 'lib', 'wasm', 'wasm_exec.js'), join(goroot, 'misc', 'wasm', 'wasm_exec.js')].find(existsSync)
if (!glue) throw new Error(`wasm_exec.js not found under ${goroot}`)
copyFileSync(glue, join(out, 'wasm_exec.js'))
