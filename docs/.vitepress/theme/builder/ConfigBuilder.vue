<script setup lang="ts">
import { computed, onMounted, ref, shallowRef } from 'vue'
import settingsJson from '../../../data/settings.generated.json'
import type { BuilderState, Format, Register, SettingDef } from './types'
import { defaultState, effectiveEnv, envGet, findTrap, isActive, isTruthy, setProxied, setTrap, setValue, defaultOf } from './state'
import { hints, LOOPBACK_TRUSTED } from './hints'
import { loadChecker, type Checker } from './checker'
import { serialize, importEnv } from './serializer'
import { SHARE_PROBLEM_TEXT, decodeShare, encodeState } from './hash'
import { settingGroups, trapFields, trapGroups } from './groups'

const reg = settingsJson as unknown as Register

const state = ref<BuilderState>(defaultState())
const format = ref<Format>('env')
const search = ref('')
const importText = ref('')
const importMsg = ref('')
const copied = ref('')
const shareMsg = ref('')

const formats: Array<{ id: Format; label: string }> = [
  { id: 'env', label: 'Env file' },
  { id: 'compose', label: 'docker-compose.yml' },
  { id: 'run', label: 'docker run' }
]

const groups = trapGroups(reg)
const sGroups = settingGroups(reg)

const env = computed(() => effectiveEnv(state.value))
const checker = shallowRef<Checker | null>(null)
const checkFailed = ref('')
const issues = computed(() => (checker.value ? checker.value.check(env.value) : []))
const advice = computed(() => hints(reg, state.value))
const hasErrors = computed(() => issues.value.some((i) => i.level === 'error'))
const output = computed(() => serialize(reg, state.value, format.value))
const proxyChoices = computed(() =>
  state.value.traps.filter((t) => findTrap(reg, t)?.transport === 'TCP')
)
const proxyOn = computed(() => state.value.proxied.length > 0)
const crowdsecOn = computed(() => isTruthy(envGet(reg, env.value, 'RAN_CROWDSEC')))

const query = computed(() => search.value.trim().toLowerCase())
const visibleGroups = computed(() =>
  sGroups
    .map((g) => ({
      ...g,
      settings: g.settings.filter((s) => {
        if (query.value) return (s.name + ' ' + s.summary).toLowerCase().includes(query.value)
        return isActive(reg, s, env.value)
      })
    }))
    .filter((g) => g.settings.length > 0)
)

function commit(next: BuilderState) {
  state.value = next
  try {
    history.replaceState(null, '', location.pathname + location.search + '#' + encodeState(next))
  } catch {
    // the URL is a convenience only
  }
}

onMounted(() => {
  loadChecker(import.meta.env.BASE_URL).then(
    (c) => { checker.value = c },
    (e) => { checkFailed.value = e instanceof Error ? e.message : String(e) }
  )
  try {
    if (location.hash.length > 1) {
      const r = decodeShare(location.hash, reg)
      state.value = r.state
      if (r.problem) shareMsg.value = SHARE_PROBLEM_TEXT
      else if (r.dropped.length) shareMsg.value = `Share link: ignored unknown entries (${r.dropped.join(', ')}).`
    }
  } catch {
    state.value = defaultState()
    shareMsg.value = SHARE_PROBLEM_TEXT
  }
})

function toggleTrap(name: string, ev: Event) {
  commit(setTrap(state.value, name, (ev.target as HTMLInputElement).checked))
}
function toggleProxied(name: string, ev: Event) {
  commit(setProxied(state.value, name, (ev.target as HTMLInputElement).checked))
}
function current(key: string): string {
  return state.value.values[key] ?? defaultOf(reg, key)
}
function onText(key: string, ev: Event) {
  commit(setValue(reg, state.value, key, (ev.target as HTMLInputElement).value))
}
function onBool(key: string, ev: Event) {
  commit(setValue(reg, state.value, key, (ev.target as HTMLInputElement).checked ? 'on' : 'off'))
}
function isOn(def: SettingDef): boolean {
  return isTruthy(envGet(reg, env.value, def.name))
}
function reset() {
  commit(defaultState())
  shareMsg.value = ''
  importMsg.value = ''
}

function toggleProxy(ev: Event) {
  const on = (ev.target as HTMLInputElement).checked
  let next = state.value
  if (on) {
    const web = next.traps.filter((t) => ['http', 'https'].includes(t))
    if (web.length > 0) {
      for (const t of web) next = setProxied(next, t, true)
    }
    if (!next.values.RAN_PROXY_TRUSTED) {
      next = setValue(reg, next, 'RAN_PROXY_TRUSTED', '172.16.0.0/12')
    }
  } else {
    next = { ...next, proxied: [] }
    next = setValue(reg, next, 'RAN_PROXY_TRUSTED', '')
  }
  commit(next)
}

function toggleCrowdsec(ev: Event) {
  const on = (ev.target as HTMLInputElement).checked
  let next = state.value
  if (on) {
    next = setValue(reg, next, 'RAN_CROWDSEC', 'on')
    if (!next.values.RAN_CROWDSEC_URL) next = setValue(reg, next, 'RAN_CROWDSEC_URL', 'http://crowdsec:8080')
    if (!next.values.RAN_CROWDSEC_MACHINE_ID) next = setValue(reg, next, 'RAN_CROWDSEC_MACHINE_ID', 'ran-honeypot')
  } else {
    next = setValue(reg, next, 'RAN_CROWDSEC', '')
    next = setValue(reg, next, 'RAN_CROWDSEC_URL', '')
    next = setValue(reg, next, 'RAN_CROWDSEC_MACHINE_ID', '')
  }
  commit(next)
}

async function copy(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = label
  } catch {
    copied.value = 'Copy failed: select the text manually'
  }
  setTimeout(() => (copied.value = ''), 2500)
}
function copyOutput() {
  copy(output.value.text, 'Copied')
}
function copyLink() {
  const url = location.origin + location.pathname + location.search + '#' + encodeState(state.value)
  copy(url, 'Link copied')
}

function doImport() {
  const r = importEnv(reg, importText.value)
  commit(r.state)
  const parts = [`Imported ${r.state.traps.length} trap(s) and ${Object.keys(r.state.values).length} setting(s).`]
  if (r.unknown.length) parts.push(`Unknown keys ignored: ${r.unknown.join(', ')}.`)
  if (r.ignored.length) parts.push(`Not kept (secret): ${r.ignored.join(', ')}.`)
  importMsg.value = parts.join(' ')
}
</script>

<template>
  <div class="cb">
    <p v-if="shareMsg" class="cb-banner" role="alert">{{ shareMsg }}</p>

    <!-- Import -->
    <details class="cb-sec">
      <summary><h3>Import existing config</h3></summary>
      <textarea v-model="importText" rows="6" placeholder="RAN_TRAPS=ssh,http" aria-label="Env file to import"></textarea>
      <div class="cb-actions">
        <button class="cb-btn" @click="doImport">Import</button>
        <span class="cb-muted" aria-live="polite">{{ importMsg }}</span>
      </div>
    </details>

    <!-- Traps -->
    <section class="cb-sec">
      <h3>Traps</h3>
      <div v-for="g in groups" :key="g.id" class="cb-group">
        <h4>
          {{ g.title }}
          <small v-if="g.note" class="cb-note">{{ g.note }}</small>
        </h4>
        <div class="cb-traps">
          <div v-for="t in g.traps" :key="t.name" class="cb-trap" :class="{ on: state.traps.includes(t.name) }">
            <label class="cb-check">
              <input type="checkbox" :checked="state.traps.includes(t.name)" @change="toggleTrap(t.name, $event)" />
              <span>{{ t.name }}</span>
              <small>{{ t.transport.toLowerCase() }}{{ t.default_addr ? ' ' + t.default_addr : '' }}</small>
            </label>
            <details v-if="state.traps.includes(t.name) && trapFields(reg, t.name).length" :open="t.addressless">
              <summary>Options</summary>
              <label v-for="f in trapFields(reg, t.name)" :key="f.key" class="cb-field">
                <span :title="f.def.summary">{{ f.key }}</span>
                <input
                  type="text"
                  :value="state.values[f.key] ?? ''"
                  :placeholder="f.placeholder"
                  @change="onText(f.key, $event)"
                />
              </label>
            </details>
          </div>
        </div>
      </div>
    </section>

    <!-- Proxy protocol -->
    <section class="cb-sec">
      <h3>Proxy protocol</h3>
      <label class="cb-check cb-toggle">
        <input type="checkbox" :checked="proxyOn" @change="toggleProxy" />
        <strong>Enable PROXY protocol</strong>
        <span class="cb-muted">Web traps sit behind a reverse proxy that sends a PROXY v2 header.</span>
      </label>
      <div v-if="proxyOn" class="cb-sub">
        <div class="cb-proxied">
          <strong>Traps behind the proxy</strong>
          <label v-for="t in proxyChoices" :key="t" class="cb-check">
            <input type="checkbox" :checked="state.proxied.includes(t)" @change="toggleProxied(t, $event)" />
            {{ t }}
          </label>
        </div>
        <label class="cb-field">
          <span>RAN_PROXY_TRUSTED</span>
          <input
            type="text"
            :value="current('RAN_PROXY_TRUSTED')"
            placeholder="172.16.0.0/12"
            @change="onText('RAN_PROXY_TRUSTED', $event)"
          />
          <small>For a shared network namespace (containers in one pod, or <code>network_mode: service:...</code>) set to <code>{{ LOOPBACK_TRUSTED }}</code>.</small>
        </label>
      </div>
    </section>

    <!-- CrowdSec -->
    <section class="cb-sec">
      <h3>CrowdSec</h3>
      <label class="cb-check cb-toggle">
        <input type="checkbox" :checked="crowdsecOn" @change="toggleCrowdsec" />
        <strong>Report alerts to CrowdSec</strong>
        <span class="cb-muted">Push classified alerts to a CrowdSec local API whose profiles decide the bans.</span>
      </label>
      <div v-if="crowdsecOn" class="cb-sub">
        <label class="cb-field">
          <span>RAN_CROWDSEC_URL</span>
          <input
            type="text"
            :value="current('RAN_CROWDSEC_URL')"
            placeholder="http://crowdsec:8080"
            @change="onText('RAN_CROWDSEC_URL', $event)"
          />
        </label>
        <label class="cb-field">
          <span>RAN_CROWDSEC_MACHINE_ID</span>
          <input
            type="text"
            :value="current('RAN_CROWDSEC_MACHINE_ID')"
            placeholder="ran-honeypot"
            @change="onText('RAN_CROWDSEC_MACHINE_ID', $event)"
          />
        </label>
        <p class="cb-muted">The password is never asked for: the export contains CHANGE_ME.</p>
      </div>
    </section>

    <!-- Settings -->
    <section class="cb-sec">
      <h3>Settings</h3>
      <input v-model="search" class="cb-search" type="search" placeholder="Search settings" aria-label="Search settings" />
      <p v-if="query" class="cb-muted">Showing all matches, including settings whose feature is switched off.</p>
      <template v-for="g in visibleGroups" :key="g.id">
        <details v-if="g.advanced" class="cb-group" :open="!!query">
          <summary>{{ g.title }} <small class="cb-note">advanced</small></summary>
          <div class="cb-fields">
            <div v-for="s in g.settings" :key="s.name" class="cb-field">
              <span :title="s.summary">{{ s.name }}</span>
              <input v-if="s.kind === 'bool'" type="checkbox" :checked="isOn(s)" @change="onBool(s.name, $event)" />
              <select v-else-if="s.kind === 'enum'" :value="current(s.name)" @change="onText(s.name, $event)">
                <option v-for="o in s.enum" :key="o" :value="o">{{ o }}</option>
              </select>
              <input v-else type="text" :value="current(s.name)" :placeholder="s.default" @change="onText(s.name, $event)" />
              <small>{{ s.summary }}</small>
            </div>
          </div>
        </details>
        <div v-else class="cb-group">
          <h4>{{ g.title }}</h4>
          <div class="cb-fields">
            <div v-for="s in g.settings" :key="s.name" class="cb-field">
              <span :title="s.summary">{{ s.name }}</span>
              <input v-if="s.kind === 'bool'" type="checkbox" :checked="isOn(s)" @change="onBool(s.name, $event)" />
              <select v-else-if="s.kind === 'enum'" :value="current(s.name)" @change="onText(s.name, $event)">
                <option v-for="o in s.enum" :key="o" :value="o">{{ o }}</option>
              </select>
              <input v-else type="text" :value="current(s.name)" :placeholder="s.default" @change="onText(s.name, $event)" />
              <small>{{ s.summary }}</small>
            </div>
          </div>
        </div>
      </template>
    </section>

    <!-- Check -->
    <section class="cb-sec">
      <h3>Check</h3>
      <p v-if="checkFailed" class="cb-issues-note">The rule check could not be loaded ({{ checkFailed }}). Run <code>ran check-config</code> on the result instead.</p>
      <p v-else-if="!checker" class="cb-muted">Loading the rule check...</p>
      <p v-else-if="issues.length === 0 && advice.length === 0" class="cb-ok">No problems found.</p>
      <ul class="cb-issues">
        <li v-for="i in issues" :key="i.id" :class="i.level">
          <strong>{{ i.level === 'error' ? 'Error' : 'Warning' }}:</strong> {{ i.message }}
        </li>
      </ul>
      <ul v-if="advice.length" class="cb-issues">
        <li v-for="h in advice" :key="h.id" class="hint">
          {{ h.message }}
          <pre v-if="h.code"><code>{{ h.code }}</code></pre>
        </li>
      </ul>
    </section>

    <!-- Output -->
    <section class="cb-sec">
      <h3>Output</h3>
      <p v-if="hasErrors" class="cb-banner" role="alert">Output has errors: fix the issues above.</p>
      <div class="cb-tabs" role="tablist">
        <button
          v-for="f in formats"
          :key="f.id"
          role="tab"
          :aria-selected="format === f.id"
          :class="{ on: format === f.id }"
          @click="format = f.id"
        >
          {{ f.label }}
        </button>
      </div>
      <pre class="cb-out"><code>{{ output.text }}</code></pre>
      <p v-for="n in output.notes" :key="n" class="cb-issues-note">{{ n }}</p>
      <div class="cb-actions">
        <button class="cb-btn primary" @click="copyOutput">Copy</button>
        <button class="cb-btn" @click="copyLink">Share link</button>
        <button class="cb-btn" @click="reset">Reset</button>
        <span class="cb-muted" aria-live="polite">{{ copied }}</span>
      </div>
      <p class="cb-muted">Only values that differ from the default are written. Nothing leaves this page.</p>
    </section>
  </div>
</template>

<style scoped>
.cb { margin-top: 16px; }
.cb-sec { margin-bottom: 8px; }
.cb h3 { margin-top: 24px; margin-bottom: 8px; }
.cb h4 { margin: 16px 0 8px; font-size: 1rem; }
.cb-note { font-weight: 400; color: var(--vp-c-text-2); margin-left: 6px; }
.cb-banner { margin: 8px 0; padding: 8px 12px; border-radius: 8px; border-left: 4px solid var(--vp-c-danger-1); background: var(--vp-c-danger-soft); }
.cb-muted { color: var(--vp-c-text-2); font-size: 0.875rem; }
.cb-ok { color: var(--vp-c-green-1); }
.cb-traps, .cb-fields { display: grid; gap: 8px; grid-template-columns: repeat(auto-fill, minmax(min(100%, 220px), 1fr)); }
.cb-trap, .cb-field {
  display: flex; flex-direction: column; gap: 4px; padding: 10px 12px;
  border: 1px solid var(--vp-c-divider); border-radius: 8px; background: var(--vp-c-bg-soft);
  min-width: 0;
}
.cb-trap.on { border-color: var(--vp-c-brand-1); background: var(--vp-c-brand-soft); }
.cb-check { display: flex; align-items: center; gap: 8px; cursor: pointer; flex-wrap: wrap; }
.cb-check small { color: var(--vp-c-text-2); }
.cb-toggle { margin-bottom: 8px; }
.cb-toggle .cb-muted { display: block; margin-left: 26px; }
.cb-sub { margin-top: 8px; display: flex; flex-direction: column; gap: 12px; }
.cb-proxied { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; }
.cb-field span { font-family: var(--vp-font-family-mono); font-size: 0.8rem; overflow-wrap: anywhere; }
.cb-field small { color: var(--vp-c-text-2); font-size: 0.78rem; }
.cb input[type='text'], .cb input[type='search'], .cb select, .cb textarea {
  width: 100%; box-sizing: border-box; padding: 6px 8px; font: inherit; font-size: 0.9rem;
  color: var(--vp-c-text-1); background: var(--vp-c-bg); border: 1px solid var(--vp-c-divider); border-radius: 6px;
}
.cb textarea { font-family: var(--vp-font-family-mono); }
.cb-search { margin-bottom: 8px; }
.cb details > summary { cursor: pointer; font-weight: 600; margin: 8px 0; }
.cb-trap details { margin-top: 4px; }
.cb-issues { list-style: none; padding: 0; margin: 8px 0; }
.cb-issues li { margin: 6px 0; padding: 8px 12px; border-radius: 8px; border-left: 4px solid var(--vp-c-divider); background: var(--vp-c-bg-soft); }
.cb-issues li.error { border-left-color: var(--vp-c-danger-1); }
.cb-issues li.warning { border-left-color: var(--vp-c-warning-1); }
.cb-issues li.hint { border-left-color: var(--vp-c-brand-1); }
.cb-issues pre { margin: 8px 0 0; overflow-x: auto; }
.cb-issues-note { border-left: 4px solid var(--vp-c-warning-1); padding: 8px 12px; background: var(--vp-c-bg-soft); border-radius: 8px; }
.cb-tabs { display: flex; flex-wrap: wrap; gap: 4px; }
.cb-tabs button, .cb-btn {
  padding: 6px 12px; font: inherit; font-size: 0.9rem; cursor: pointer; color: var(--vp-c-text-1);
  background: var(--vp-c-bg-soft); border: 1px solid var(--vp-c-divider); border-radius: 6px;
}
.cb-tabs button.on, .cb-btn.primary { color: var(--vp-c-white); background: var(--vp-c-brand-2); border-color: var(--vp-c-brand-2); }
.cb-out { margin: 8px 0; padding: 12px 16px; overflow-x: auto; background: var(--vp-code-block-bg); border-radius: 8px; font-size: 0.85rem; line-height: 1.5; }
.cb-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0; }
@media (max-width: 640px) {
  .cb-traps, .cb-fields { grid-template-columns: 1fr; }
}
</style>
