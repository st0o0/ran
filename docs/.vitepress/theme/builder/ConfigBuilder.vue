<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import settingsJson from '../../../data/settings.generated.json'
import type { BuilderState, Format, Register, ScenarioId, SettingDef } from './types'
import { defaultState, effectiveEnv, envGet, findTrap, isActive, setProxied, setTrap, setValue, defaultOf } from './state'
import { evaluate, hints } from './rules'
import { serialize, importEnv } from './serializer'
import { decodeState, encodeState } from './hash'
import { SCENARIOS, applyScenario, scenarioHints } from './scenarios'
import { settingGroups, trapFields, trapGroups } from './groups'

const reg = settingsJson as unknown as Register

const state = ref<BuilderState>(defaultState())
const format = ref<Format>('env')
const search = ref('')
const importText = ref('')
const importMsg = ref('')
const copied = ref('')

const formats: Array<{ id: Format; label: string }> = [
  { id: 'env', label: 'Env file' },
  { id: 'compose', label: 'docker-compose.yml' },
  { id: 'run', label: 'docker run' }
]

const groups = trapGroups(reg)
const sGroups = settingGroups(reg)

const env = computed(() => effectiveEnv(state.value))
const issues = computed(() => evaluate(reg, state.value))
const advice = computed(() => [...scenarioHints(reg, state.value), ...hints(reg, state.value)])
const output = computed(() => serialize(reg, state.value, format.value))
const proxyChoices = computed(() =>
  state.value.traps.filter((t) => findTrap(reg, t)?.transport === 'TCP')
)
const proxyScenario = computed(
  () => state.value.scenario === 'reverse-proxy' || state.value.scenario === 'shared-namespace'
)

const query = computed(() => search.value.trim().toLowerCase())
const visibleGroups = computed(() =>
  sGroups
    .map((g) => ({
      ...g,
      settings: g.settings.filter((s) => {
        if (s.name === 'RAN_PROXY_PROTOCOL' && proxyScenario.value) return false
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
  try {
    if (location.hash.length > 1) state.value = decodeState(location.hash)
  } catch {
    state.value = defaultState()
  }
})

function pickScenario(id: ScenarioId) {
  commit(applyScenario(reg, state.value, id))
}
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
  return envGet(reg, env.value, def.name).toLowerCase() === 'on'
}
function reset() {
  commit(defaultState())
  importMsg.value = ''
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
    <section class="cb-sec">
      <h2>1. Scenario</h2>
      <div class="cb-scenarios" role="radiogroup" aria-label="Scenario">
        <label
          v-for="s in SCENARIOS"
          :key="s.id"
          class="cb-card"
          :class="{ on: state.scenario === s.id }"
        >
          <input
            type="radio"
            name="scenario"
            :value="s.id"
            :checked="state.scenario === s.id"
            @change="pickScenario(s.id)"
          />
          <strong>{{ s.label }}</strong>
          <span>{{ s.summary }}</span>
        </label>
      </div>
      <div v-if="proxyScenario" class="cb-proxied">
        <strong>Traps behind the proxy</strong>
        <label v-for="t in proxyChoices" :key="t" class="cb-check">
          <input type="checkbox" :checked="state.proxied.includes(t)" @change="toggleProxied(t, $event)" />
          {{ t }}
        </label>
      </div>
    </section>

    <section class="cb-sec">
      <h2>2. Traps</h2>
      <div v-for="g in groups" :key="g.id" class="cb-group">
        <h3>
          {{ g.title }}
          <small v-if="g.note" class="cb-note">{{ g.note }}</small>
        </h3>
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

    <section class="cb-sec">
      <h2>3. Settings</h2>
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
          <h3>{{ g.title }}</h3>
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
      <p class="cb-muted">The CrowdSec password is never asked for: the export contains CHANGE_ME.</p>
    </section>

    <section class="cb-sec">
      <h2>4. Check</h2>
      <p v-if="issues.length === 0" class="cb-ok">No problems found.</p>
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

    <section class="cb-sec">
      <h2>5. Output</h2>
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

    <section class="cb-sec">
      <h2>Import an env file</h2>
      <textarea v-model="importText" rows="6" placeholder="RAN_TRAPS=ssh,http" aria-label="Env file to import"></textarea>
      <div class="cb-actions">
        <button class="cb-btn" @click="doImport">Import</button>
        <span class="cb-muted" aria-live="polite">{{ importMsg }}</span>
      </div>
    </section>
  </div>
</template>

<style scoped>
.cb { margin-top: 16px; }
.cb-sec { margin-bottom: 8px; }
.cb h2 { margin-top: 32px; }
.cb h3 { margin: 16px 0 8px; font-size: 1rem; }
.cb-note { font-weight: 400; color: var(--vp-c-text-2); margin-left: 6px; }
.cb-muted { color: var(--vp-c-text-2); font-size: 0.875rem; }
.cb-ok { color: var(--vp-c-green-1); }
.cb-scenarios, .cb-traps, .cb-fields { display: grid; gap: 8px; grid-template-columns: repeat(auto-fill, minmax(min(100%, 220px), 1fr)); }
.cb-card, .cb-trap, .cb-field {
  display: flex; flex-direction: column; gap: 4px; padding: 10px 12px;
  border: 1px solid var(--vp-c-divider); border-radius: 8px; background: var(--vp-c-bg-soft);
  min-width: 0;
}
.cb-card { cursor: pointer; position: relative; }
.cb-card input { position: absolute; opacity: 0; pointer-events: none; }
.cb-card span { font-size: 0.85rem; color: var(--vp-c-text-2); }
.cb-card.on, .cb-trap.on { border-color: var(--vp-c-brand-1); background: var(--vp-c-brand-soft); }
.cb-card:focus-within { outline: 2px solid var(--vp-c-brand-1); }
.cb-check { display: flex; align-items: center; gap: 8px; cursor: pointer; flex-wrap: wrap; }
.cb-check small { color: var(--vp-c-text-2); }
.cb-proxied { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin-top: 12px; }
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
  .cb-scenarios, .cb-traps, .cb-fields { grid-template-columns: 1fr; }
}
</style>
