<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  // region Settings [DOMAIN(9): UI; CONCEPT(7]: GlobalSettings; TECH(6]: svelte]
  // Global settings only (AI provider). Per-VM credentials live in the VM detail pane now.
  let ai = { api_url: '', model: '', has_key: false, auto_approve: false }
  let aiKey = '' // leave empty to keep existing
  let aiMsg = ''
  let aiOk = false
  let aiBusy = false

  async function loadAI() {
    try {
      ai = await api.getAISettings()
    } catch (e) {
      aiMsg = e.message
      aiOk = false
    }
  }

  async function saveAI() {
    aiBusy = true
    aiMsg = ''
    try {
      await api.updateAISettings({ api_url: ai.api_url, api_key: aiKey, model: ai.model, auto_approve: ai.auto_approve })
      aiKey = ''
      await loadAI()
      aiMsg = 'saved — assistant reloaded, no restart needed'
      aiOk = true
    } catch (e) {
      aiMsg = e.message
      aiOk = false
    } finally {
      aiBusy = false
    }
  }

  onMount(loadAI)
</script>

<div class="max-w-3xl mx-auto space-y-6">
  <section class="hud-panel p-5 space-y-3">
    <div class="hud-label text-neon-cyan">ai&nbsp;provider</div>
    <div class="grid grid-cols-2 gap-3">
      <label class="block space-y-1 col-span-2">
        <span class="hud-label">api_url</span>
        <input class="hud-input" bind:value={ai.api_url} placeholder="https://api.openai.com/v1" />
      </label>
      <label class="block space-y-1">
        <span class="hud-label">model</span>
        <input class="hud-input" bind:value={ai.model} placeholder="gpt-4o-mini" />
      </label>
      <label class="block space-y-1">
        <span class="hud-label">api_key {ai.has_key ? '(set ✓ — leave empty to keep)' : ''}</span>
        <input class="hud-input" type="password" bind:value={aiKey} placeholder={ai.has_key ? '••••••' : 'sk-...'} />
      </label>
    </div>
    <label class="flex items-center gap-2 cursor-pointer select-none pt-1">
      <input type="checkbox" class="accent-neon-amber" bind:checked={ai.auto_approve} />
      <span class="hud-label {ai.auto_approve ? 'text-neon-amber' : ''}">auto-approve AI actions</span>
      <span class="text-[11px] text-hud-dim">// off (default): VMPilot proposes, you approve each command. on: proposed commands run immediately.</span>
    </label>
    <div class="flex items-center gap-3">
      <button class="hud-btn hud-btn-primary" on:click={saveAI} disabled={aiBusy}>
        {aiBusy ? 'saving…' : aiMsg && aiOk ? 'saved ✓' : 'save'}
      </button>
      {#if aiMsg}
        <span class="text-xs font-mono px-2 py-1 rounded border {aiOk ? 'text-neon-green border-neon-green/40 bg-neon-green/5' : 'text-neon-red border-neon-red/40 bg-neon-red/5'}">{aiMsg}</span>
      {/if}
    </div>
  </section>

  <section class="hud-panel p-5">
    <div class="hud-label text-hud-dim">more settings</div>
    <p class="text-xs text-hud-dim mt-2">// channels, users, retention — upcoming</p>
  </section>
</div>
