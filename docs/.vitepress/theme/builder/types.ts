// Shared types of the config builder. Framework free.

export type SettingKind = 'bool' | 'int' | 'duration' | 'string' | 'enum' | 'list' | 'addr'

export interface SettingDef {
  name: string
  kind: SettingKind
  default: string
  group: string
  summary: string
  enum?: string[]
  requires?: string[]
  /** Per-trap family: name is a template such as RAN_<PROTO>_ADDR. */
  family?: string
  traps?: string[]
  /** Inclusive bounds of an int setting, as Load enforces them (omitted when unset). */
  min?: number
  max?: number
}

export interface TrapDef {
  name: string
  transport: 'TCP' | 'UDP'
  default_addr: string
  addr_var: string
  addressless: boolean
}

export interface Register {
  settings: SettingDef[]
  traps: TrapDef[]
}

export interface BuilderCase {
  id: string
  env: Record<string, string>
  expect: 'ok' | 'warning' | 'error'
  message_contains?: string
}

export interface BuilderState {
  /** Enabled traps (becomes RAN_TRAPS). */
  traps: string[]
  /** Settings that differ from the default, keyed by variable name. */
  values: Record<string, string>
  /** Traps behind a reverse proxy (enables PROXY protocol for these). */
  proxied: string[]
}

export type Level = 'error' | 'warning'

export interface Issue {
  id: string
  level: Level
  message: string
}

export interface Hint {
  id: string
  message: string
  code?: string
}

export type Format = 'env' | 'compose' | 'run'

export interface Output {
  text: string
  notes: string[]
}

export interface ImportResult {
  state: BuilderState
  /** Keys that are not part of the register. */
  unknown: string[]
  /** Keys that were read but deliberately not kept (secrets). */
  ignored: string[]
}

export const SECRET_KEYS = ['RAN_CROWDSEC_PASSWORD']
export const PASSWORD_PLACEHOLDER = 'CHANGE_ME'
