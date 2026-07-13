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

  // ── 2FA ──
  let twofa = { enabled: false, loaded: false }
  let setup = null // {secret, otpauth_uri, qr_data_url, already_on}
  let code = ''
  let backupCodes = null
  let twofaMsg = ''
  let twofaErr = ''
  let twofaBusy = false
  let disablePw = ''

  async function load2FA() {
    try { twofa = { ...(await api.twoFAStatus()), loaded: true } } catch (_) {}
  }

  async function startSetup() {
    twofaErr = ''; setup = null; backupCodes = null
    twofaBusy = true
    try { setup = await api.twoFASetup() } catch (e) { twofaErr = e.message } finally { twofaBusy = false }
  }

  async function enable() {
    twofaErr = ''
    twofaBusy = true
    try {
      const res = await api.twoFAEnable(code.trim())
      backupCodes = res.backup_codes || []
      twofa = { enabled: true, loaded: true }
      setup = null
      code = ''
    } catch (e) { twofaErr = e.message } finally { twofaBusy = false }
  }

  async function disable() {
    twofaErr = ''
    twofaBusy = true
    try {
      await api.twoFADisable(disablePw)
      twofa = { enabled: false, loaded: true }
      disablePw = ''
      twofaMsg = '2FA disabled'
    } catch (e) { twofaErr = e.message } finally { twofaBusy = false }
  }

  onMount(load2FA)
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

  <section class="hud-panel p-5 space-y-3">
    <div class="flex items-center gap-2">
      <div class="hud-label text-neon-cyan">two-factor (2fa)</div>
      {#if twofa.loaded}
        <span class="hud-label {twofa.enabled ? 'text-neon-green' : 'text-hud-dim'} ml-auto">{twofa.enabled ? 'on' : 'off'}</span>
      {/if}
    </div>
    <p class="text-xs text-hud-dim">// recommended. while any VM stores SSH credentials, 2FA cannot be disabled — privileged access needs a hardened login.</p>

    {#if twofa.enabled}
      <div class="space-y-2">
        <p class="text-xs text-neon-green font-mono">2FA is on. A TOTP code (or backup code) is required at login.</p>
        <label class="block space-y-1">
          <span class="hud-label">password (to disable)</span>
          <input class="hud-input" type="password" bind:value={disablePw} placeholder="••••••" />
        </label>
        <button class="hud-btn !text-neon-red border-neon-red/40" on:click={disable} disabled={twofaBusy || !disablePw}>{twofaBusy ? '…' : 'disable 2FA'}</button>
      </div>
    {:else if !setup}
      <button class="hud-btn hud-btn-primary" on:click={startSetup} disabled={twofaBusy}>{twofaBusy ? '…' : 'enable 2FA'}</button>
    {:else}
      <div class="space-y-3">
        <p class="text-xs text-hud-dim">1. scan with your authenticator app, or enter the secret manually.</p>
        <div class="flex gap-3 items-start">
          {#if setup.qr_data_url}<img src={setup.qr_data_url} alt="2FA QR" class="w-36 h-36 bg-white p-1 rounded" />{/if}
          <div class="text-xs font-mono space-y-1">
            <div class="hud-label text-hud-dim">secret</div>
            <div class="text-emerald-200 break-all">{setup.secret}</div>
          </div>
        </div>
        <label class="block space-y-1">
          <span class="hud-label">2. enter the 6-digit code from your app</span>
          <input class="hud-input" bind:value={code} placeholder="123456" />
        </label>
        <button class="hud-btn hud-btn-primary" on:click={enable} disabled={twofaBusy || !code}>{twofaBusy ? '…' : 'confirm & enable'}</button>
      </div>
    {/if}

    {#if backupCodes}
      <div class="border border-neon-amber/40 rounded p-3 bg-neon-amber/5 space-y-2">
        <div class="hud-label text-neon-amber">backup codes — store these safely (shown once)</div>
        <div class="font-mono text-xs grid grid-cols-2 gap-1">{#each backupCodes as c}<span class="text-emerald-200">{c}</span>{/each}</div>
        <p class="text-[11px] text-hud-dim">each works as a one-time 2FA code if you lose your device.</p>
      </div>
    {/if}
    {#if twofaMsg}<div class="text-xs text-neon-green font-mono">{twofaMsg}</div>{/if}
    {#if twofaErr}<div class="text-xs text-neon-red font-mono">{twofaErr}</div>{/if}
  </section>

  <section class="hud-panel p-5">
    <div class="hud-label text-hud-dim">more settings</div>
    <p class="text-xs text-hud-dim mt-2">// channels, users, retention — upcoming</p>
  </section>
</div>
