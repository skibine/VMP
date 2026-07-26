<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { providers, findProvider } from '../lib/providers.js'

  // region Settings [DOMAIN(9): UI; CONCEPT(7]: GlobalSettings; TECH(6]: svelte]
  // Global settings only (AI provider). Per-VM credentials live in the VM detail pane now.
  let ai = { api_url: '', model: '', has_key: false, auto_approve: false }
  let aiKey = '' // leave empty to keep existing
  let aiMsg = ''
  let aiOk = false
  let aiBusy = false

  // Provider-preset state (#24/#25/#26): which preset is active + its capabilities.
  let selectedProvider = 'custom' // preset id (matches providers.js)
  let keyRequired = true          // local servers need no key -> hidden key field
  let isLocal = false
  let fetchedModels = null        // [id] returned by the provider /models proxy
  let modelFetching = false
  let localResults = null         // [{id,label,alive,models}] from probeLocalAI
  let localProbing = false

  // syncProvider derives the active preset from the loaded api_url (best-effort -> Custom).
  function syncProvider() {
    const p = findProvider(ai.api_url)
    if (p) {
      selectedProvider = p.id
      keyRequired = p.key_required
      isLocal = p.local
    } else {
      selectedProvider = 'custom'
      keyRequired = true
      isLocal = false
    }
  }

  // applyPreset fills api_url/model from a chosen preset; Custom leaves fields untouched.
  function applyPreset(p) {
    selectedProvider = p.id
    keyRequired = p.key_required
    isLocal = p.local
    fetchedModels = null
    localResults = null
    if (p.id !== 'custom') {
      ai.api_url = p.api_url
      if (p.default_model) ai.model = p.default_model
    }
  }

  function onProviderSelect(e) {
    const id = e.currentTarget.value
    const p = providers.find((x) => x.id === id) || providers[providers.length - 1]
    applyPreset(p)
  }

  async function loadAI() {
    try {
      ai = await api.getAISettings()
      syncProvider()
    } catch (e) {
      aiMsg = e.message
      aiOk = false
    }
  }

  async function saveAI() {
    aiBusy = true
    aiMsg = ''
    try {
      // Local servers ignore the key, but the store's Configured() requires a non-empty value;
      // send a harmless placeholder so a local provider counts as configured.
      const keyToSend = isLocal ? aiKey || 'local' : aiKey
      await api.updateAISettings({ api_url: ai.api_url, api_key: keyToSend, model: ai.model, auto_approve: ai.auto_approve })
      aiKey = ''
      await loadAI()
      aiMsg = $t('set.savedMsg')
      aiOk = true
    } catch (e) {
      aiMsg = e.message
      aiOk = false
    } finally {
      aiBusy = false
    }
  }

  // fetchModels lists models from the STORED provider config (key stays server-side).
  async function fetchModels() {
    modelFetching = true
    aiMsg = ''
    aiOk = false
    try {
      const res = await api.aiModels()
      fetchedModels = res.models || []
      aiMsg = fetchedModels.length ? $t('set.modelsFound', { n: fetchedModels.length }) : $t('set.noModels')
      aiOk = fetchedModels.length > 0
    } catch (e) {
      fetchedModels = null
      aiMsg = e.message || $t('set.fetchFail')
    } finally {
      modelFetching = false
    }
  }

  async function probeLocal() {
    localProbing = true
    aiMsg = ''
    aiOk = false
    try {
      const res = await api.probeLocalAI()
      localResults = res.targets || []
      const alive = localResults.filter((t) => t.alive).length
      aiMsg = alive ? $t('set.localDetected', { n: alive }) : $t('set.noLocal')
      aiOk = alive > 0
    } catch (e) {
      aiMsg = e.message
    } finally {
      localProbing = false
    }
  }

  function selectLocal(t) {
    const p = providers.find((x) => x.id === t.id)
    if (p) applyPreset(p)
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
      twofaMsg = $t('set.disable2fa')
    } catch (e) { twofaErr = e.message } finally { twofaBusy = false }
  }

  onMount(load2FA)
</script>

<div class="max-w-3xl mx-auto space-y-6">
  <section class="hud-panel p-5 space-y-3">
    <div class="hud-label text-neon-cyan">{$t('set.aiTitle')}</div>

    <label class="block space-y-1">
      <span class="hud-label">{$t('set.provider')}</span>
      <select class="hud-input" value={selectedProvider} on:change={onProviderSelect}>
        {#each providers as p}<option value={p.id}>{p.label}</option>{/each}
      </select>
    </label>

    <div class="grid grid-cols-2 gap-3">
      <label class="block space-y-1 col-span-2">
        <span class="hud-label">api_url</span>
        <input class="hud-input" bind:value={ai.api_url} placeholder="https://api.openai.com/v1" />
      </label>

      {#if keyRequired}
        <label class="block space-y-1">
          <span class="hud-label">{$t('set.model')}</span>
          <input class="hud-input" bind:value={ai.model} placeholder="gpt-4o-mini" list="ai-model-list" />
        </label>
        <label class="block space-y-1">
          <span class="hud-label">api_key {ai.has_key ? $t('set.keyHint') : ''}</span>
          <input class="hud-input" type="password" bind:value={aiKey} placeholder={ai.has_key ? '••••••' : 'sk-...'} />
        </label>
      {:else}
        <label class="block space-y-1 col-span-2">
          <span class="hud-label">{$t('set.model')}</span>
          <input class="hud-input" bind:value={ai.model} placeholder="e.g. llama3.1" list="ai-model-list" />
        </label>
        <p class="text-[11px] text-hud-dim col-span-2">{$t('set.localHint')}</p>
      {/if}
    </div>

    {#if fetchedModels}
      <datalist id="ai-model-list">{#each fetchedModels as m}<option value={m}>{/each}</datalist>
    {/if}

    <div class="flex flex-wrap items-center gap-3">
      {#if !isLocal}
        <button class="hud-btn" on:click={fetchModels} disabled={modelFetching}>{modelFetching ? '…' : $t('set.fetchModels')}</button>
      {/if}
      {#if isLocal}
        <button class="hud-btn" on:click={probeLocal} disabled={localProbing}>{localProbing ? '…' : $t('set.detectLocal')}</button>
      {/if}
      <button class="hud-btn hud-btn-primary" on:click={saveAI} disabled={aiBusy}>
        {aiBusy ? $t('g.saving') : aiMsg && aiOk ? $t('g.saved') : $t('g.save')}
      </button>
      {#if aiMsg}
        <span class="text-xs font-mono px-2 py-1 rounded border {aiOk ? 'text-neon-green border-neon-green/40 bg-neon-green/5' : 'text-neon-red border-neon-red/40 bg-neon-red/5'}">{aiMsg}</span>
      {/if}
    </div>

    {#if localResults}
      <div class="space-y-1">
        <div class="hud-label text-hud-dim">{$t('set.localServers')}</div>
        {#each localResults as srv}
          <button class="hud-btn w-full !justify-start text-left" disabled={!srv.alive} on:click={() => selectLocal(srv)}>
            <span class={srv.alive ? 'text-neon-green' : 'text-hud-dim'}>{srv.alive ? '●' : '○'}</span>
            {srv.label}
            {#if srv.alive && srv.models && srv.models.length}<span class="text-hud-dim text-[11px] font-normal">// {$t('set.modelsCount', { n: srv.models.length })}</span>{/if}
          </button>
        {/each}
      </div>
    {/if}

    <label class="flex items-center gap-2 cursor-pointer select-none pt-1">
      <input type="checkbox" class="accent-neon-amber" bind:checked={ai.auto_approve} />
      <span class="hud-label {ai.auto_approve ? 'text-neon-amber' : ''}">{$t('set.autoApprove')}</span>
      <span class="text-[11px] text-hud-dim">{$t('set.autoApproveHint')}</span>
    </label>
  </section>

  <section class="hud-panel p-5 space-y-3">
    <div class="flex items-center gap-2">
      <div class="hud-label text-neon-cyan">{$t('set.2faTitle')}</div>
      {#if twofa.loaded}
        <span class="hud-label {twofa.enabled ? 'text-neon-green' : 'text-hud-dim'} ml-auto">{twofa.enabled ? $t('set.2faOn') : $t('set.2faOff')}</span>
      {/if}
    </div>
    <p class="text-xs text-hud-dim">{$t('set.2faHint')}</p>

    {#if twofa.enabled}
      <div class="space-y-2">
        <p class="text-xs text-neon-green font-mono">{$t('set.2faIsOn')}</p>
        <label class="block space-y-1">
          <span class="hud-label">{$t('set.passwordToDisable')}</span>
          <input class="hud-input" type="password" bind:value={disablePw} placeholder="••••••" />
        </label>
        <button class="hud-btn !text-neon-red border-neon-red/40" on:click={disable} disabled={twofaBusy || !disablePw}>{twofaBusy ? '…' : $t('set.disable2fa')}</button>
      </div>
    {:else if !setup}
      <button class="hud-btn hud-btn-primary" on:click={startSetup} disabled={twofaBusy}>{twofaBusy ? '…' : $t('set.enable2fa')}</button>
    {:else}
      <div class="space-y-3">
        <div class="text-[11px] font-mono text-neon-amber border border-neon-amber/30 rounded p-2 bg-neon-amber/5">
          {$t('set.2faWarn')}
        </div>
        <p class="text-xs text-hud-dim">{$t('set.2faStep1')}</p>
        <div class="flex gap-3 items-start">
          {#if setup.qr_data_url}<img src={setup.qr_data_url} alt="2FA QR" class="w-36 h-36 bg-white p-1 rounded" />{/if}
          <div class="text-xs font-mono space-y-1">
            <div class="hud-label text-hud-dim">{$t('set.secret')}</div>
            <div class="text-emerald-200 break-all">{setup.secret}</div>
          </div>
        </div>
        <label class="block space-y-1">
          <span class="hud-label">{$t('set.2faStep2')}</span>
          <input class="hud-input" bind:value={code} placeholder="123456" />
        </label>
        <button class="hud-btn hud-btn-primary" on:click={enable} disabled={twofaBusy || !code}>{twofaBusy ? '…' : $t('set.confirmEnable')}</button>
      </div>
    {/if}

    {#if backupCodes}
      <div class="border border-neon-amber/40 rounded p-3 bg-neon-amber/5 space-y-2">
        <div class="hud-label text-neon-amber">{$t('set.backupCodes')}</div>
        <div class="font-mono text-xs grid grid-cols-2 gap-1">{#each backupCodes as c}<span class="text-emerald-200">{c}</span>{/each}</div>
        <p class="text-[11px] text-hud-dim">{$t('set.backupHint')}</p>
      </div>
    {/if}
    {#if twofaMsg}<div class="text-xs text-neon-green font-mono">{twofaMsg}</div>{/if}
    {#if twofaErr}<div class="text-xs text-neon-red font-mono">{twofaErr}</div>{/if}
  </section>

  <section class="hud-panel p-5">
    <div class="hud-label text-hud-dim">{$t('set.moreTitle')}</div>
    <p class="text-xs text-hud-dim mt-2">{$t('set.moreHint')}</p>
  </section>
</div>
