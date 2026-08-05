<script>
  // region FleetMatrix [DOMAIN(7): UI; CONCEPT(8]: FleetOverview; TECH(6]: svelte]
  // Default landing: a responsive auto-fill grid of identical VM cards. Each card shows the
  // liveness lamp (green/amber/red/hollow) from stored check results (no live probe load on the
  // grid) + the per-check verdict chips. Click a card -> drill into the master-detail.
  // Pairs with the future "security // exposures" signal (a card badge) — no-root intel only.
  import { createEventDispatcher, onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { bumpAlerts, credRevision, gotoSettings } from '../lib/stores.js'
  import { coverage, vmAlerted, refreshAlertCoverage } from '../lib/alerts.js'
  import Bell from './Bell.svelte'
  import Lock from './Lock.svelte'

  const dispatch = createEventDispatcher()

  let vms = []
  let domains = []
  let health = {} // id -> {status, breakdown:[{check_type,status}]}
  let domHealth = {} // domain id -> {status, reasons}
  let loading = true
  let err = ''

  // refreshHealth re-fetches only liveness for the known VMs so card lamps don't freeze at their
  // mount-time value (the engine writes fresh results ~every 60s; without polling a newly-added
  // VM stays grey until a manual page refresh).
  async function refreshHealth() {
    if (!vms || !vms.length) return
    const entries = await Promise.all(
      vms.map(async (v) => {
        try { return [v.id, await api.vmHealth(v.id)] }
        catch (_) { return [v.id, { status: 'unknown', breakdown: [] }] }
      })
    )
    health = Object.fromEntries(entries)
  }

  async function refreshDomHealth() {
    if (!domains || !domains.length) return
    const entries = await Promise.all(
      domains.map(async (d) => {
        try { return [d.id, await api.domainHealth(d.id)] }
        catch (_) { return [d.id, { status: 'unknown', reasons: [] }] }
      })
    )
    domHealth = Object.fromEntries(entries)
  }

  async function load() {
    loading = true
    err = ''
    try {
      vms = await api.listVms()
      domains = (await api.listDomains().catch(() => [])) || []
      await Promise.all([refreshHealth(), refreshDomHealth()])
    } catch (e) {
      err = e.message
    } finally {
      loading = false
    }
  }

  // Use the backend's worst-case status directly: a critical (down) liveness check means the server
  // is DOWN — show red, never downgrade to amber just because another check still passes.
  function status(v) {
    return health[v.id]?.status || 'unknown'
  }
  // Worst non-ok check's message — the actionable "why is this degraded" reason.
  function reason(v) {
    const rank = { critical: 3, warn: 2, unknown: 1 }
    const bad = (health[v.id]?.breakdown || [])
      .filter((b) => b.status && b.status !== 'ok')
      .sort((a, b) => (rank[b.status] || 0) - (rank[a.status] || 0))[0]
    if (!bad) return ''
    return bad.message || `${bad.check_type} ${bad.status}`
  }
  function lampClass(st) {
    if (st === 'unknown') return 'border border-hud-line bg-transparent'
    // Bright LED dot (bg + matching text so the .led halo follows the status color) with pulse.
    return st === 'ok'
      ? 'bg-neon-green text-neon-green led led-pulse'
      : st === 'warn'
        ? 'bg-neon-amber text-neon-amber led led-pulse'
        : 'bg-neon-red text-neon-red led led-pulse'
  }
  function verdictKey(st) {
    return st === 'ok' ? 'mx.up' : st === 'warn' ? 'mx.warn' : st === 'critical' ? 'mx.down' : 'mx.unknown'
  }
  function verdictColor(st) {
    return st === 'ok' ? 'text-neon-green' : st === 'warn' ? 'text-neon-amber' : st === 'critical' ? 'text-neon-red' : 'text-hud-dim'
  }

  // Poll health every 30s so card lamps track the latest check results without a page refresh.
  let healthTimer
  let scanning = false
  // Domain status helpers: same LED treatment as VM cards, colored by fleet health.
  function domStatus(id) { return domHealth[id]?.status ?? 'ok' }
  function domDotClass(st) {
    if (st === 'critical') return 'bg-neon-red text-neon-red led led-pulse'
    if (st === 'warn') return 'bg-neon-amber text-neon-amber led led-pulse'
    return 'bg-neon-green text-neon-green led led-pulse'
  }
  function domTitle(d) {
    const h = domHealth[d.id]
    return h && h.reasons && h.reasons.length ? h.reasons.join('; ') : 'ok'
  }
  async function scanAllSecurity() {
    if (scanning) return
    scanning = true
    try {
      await api.exposuresScanAll()
      await refreshHealth()
    } catch (_) { /* surface via toast later */ }
    scanning = false
  }
  // Channel-aware alert model is SHARED (lib/alerts.js): one batch fetch, one "isAlerted" rule. The
  // fleet button is green (allOn) ONLY when EVERY server is alerted. A transient fetch keeps
  // last-known — bells are never blanked (W5).
  let allVmAlertBusy = false
  // allOn = every server is alerted (covered AND has a delivery channel).
  $: alertedIds = new Set(vms.filter((v) => vmAlerted(v.id, $coverage)).map((v) => v.id))
  $: allOn = vms.length > 0 && vms.every((vm) => alertedIds.has(vm.id))
  // Fleet channel picker: bulk-apply a channel set to ALL servers. in-app is now a regular
  // selectable channel (it appears in the list like telegram). Saving with channels selected
  // ensures the fleet rule (covered) + applies them; saving with none deletes the rule (off).
  let fleetPickerOpen = false
  let fleetSel = new Set()
  function openFleetPicker() {
    if (allVmAlertBusy) return
    const idsPerVm = vms.map((vm) => new Set($coverage.vmChannels.get(vm.id) || []))
    fleetSel = new Set(($coverage.channels || []).filter((c) => idsPerVm.every((s) => s.has(c.id))).map((c) => c.id))
    fleetPickerOpen = true
  }
  async function saveFleetPicker() {
    allVmAlertBusy = true
    const ids = [...fleetSel]
    try {
      await Promise.all(vms.map((vm) => api.setVMAlertChannels(vm.id, ids)))
      if (ids.length > 0) {
        if (!$coverage.fleetRule) {
          await api.createAlertRule({
            name: 'any server down', check_type: 'liveness', trigger_status: 'critical',
            severity: 'critical', cooldown_sec: 300, enabled: true,
          })
        }
        await Promise.all([...$coverage.mutedIds].map((id) => api.setAlertMute(id, false)))
      } else if ($coverage.fleetRule) {
        await api.deleteAlertRule($coverage.fleetRule.id)
      }
      fleetPickerOpen = false
      await refreshAlertCoverage()
      bumpAlerts()
    } catch (_) {} finally { allVmAlertBusy = false }
  }

  let credUnsub
  let onVisible
  onMount(() => {
    load()
    refreshAlertCoverage()
    healthTimer = setInterval(() => { refreshHealth(); refreshDomHealth() }, 30000)
    // Background tabs throttle setInterval — refresh status the moment the tab is visible/focused.
    onVisible = () => { if (!document.hidden) { refreshHealth(); refreshDomHealth() } }
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('focus', onVisible)
    // Re-fetch the VM list when SSH credentials change anywhere, so the lock badges stay live.
    credUnsub = credRevision.subscribe(() => load())
  })
  onDestroy(() => {
    clearInterval(healthTimer); credUnsub && credUnsub()
    if (onVisible) { document.removeEventListener('visibilitychange', onVisible); window.removeEventListener('focus', onVisible) }
  })
</script>

<div class="h-full overflow-auto p-4 space-y-4">
  <div class="flex items-center gap-2">
    <h2 class="font-mono text-neon-green text-lg">{$t('mx.title', { n: vms.length ?? 0 })}</h2>
    <button class="hud-btn !py-0.5" on:click={scanAllSecurity} disabled={scanning} title={$t('mx.scanAllHint')}>{scanning ? '…' : $t('mx.scanAll')}</button>
    <div class="relative inline-flex">
      <button class="hud-btn inline-flex items-center gap-1 leading-none whitespace-nowrap !py-1 !px-2.5 {allOn ? '!bg-neon-green/15 !border-neon-green/50' : ''}" on:click={() => (fleetPickerOpen ? (fleetPickerOpen = false) : openFleetPicker())} disabled={allVmAlertBusy} title={$t('mx.allVmAlertHint')}>{#if allVmAlertBusy}…{:else}<Bell size={13} cls={allOn ? 'text-neon-green' : 'text-neon-green/40'} />{/if}{$t('mx.allVmAlert')}</button>
      {#if fleetPickerOpen}
        <div class="fixed inset-0 z-[65]" on:click={() => (fleetPickerOpen = false)} on:contextmenu|preventDefault={() => (fleetPickerOpen = false)}></div>
        <div class="absolute left-0 mt-1 w-64 hud-panel p-2 z-[70] space-y-1">
          <div class="hud-label text-neon-cyan">{$t('mx.allVmAlertChannels')}</div>
          {#if $coverage.channels.length}
            <div class="max-h-48 overflow-auto space-y-0.5">
              {#each $coverage.channels as c (c.id)}
                <label class="flex items-center gap-2 text-xs font-mono cursor-pointer px-1 py-0.5 hover:bg-hud-panel2 rounded">
                  <input type="checkbox" class="accent-neon-green" checked={fleetSel.has(c.id)} on:change={(e) => { if (e.currentTarget.checked) fleetSel = new Set([...fleetSel, c.id]); else { const n = new Set(fleetSel); n.delete(c.id); fleetSel = n } }} />
                  <span class="text-neon-cyan uppercase w-16">{c.type}</span>
                  <span class="text-emerald-100 truncate">{c.name}</span>
                </label>
              {/each}
            </div>
          {:else}
            <div class="text-[10px] text-hud-dim">{$t('mx.noExternalChannel')} <button type="button" class="text-neon-cyan underline" on:click={() => gotoSettings.set(true)}>{$t('mx.configure')} →</button></div>
          {/if}
          <div class="text-[10px] text-hud-dim">{$t('mx.allVmAlertApply')}</div>
          <div class="flex items-center gap-1 pt-1">
            <button class="hud-btn hud-btn-primary !py-0.5 !text-[10px]" on:click={saveFleetPicker} disabled={allVmAlertBusy}>{$t('g.save')}</button>
            <button class="hud-btn !py-0.5 !text-[10px] ml-auto" on:click={() => (fleetPickerOpen = false)}>{$t('g.cancel')}</button>
          </div>
        </div>
      {/if}
    </div>
    <button class="hud-btn ml-auto !py-0.5" on:click={load} disabled={loading}>{loading ? '…' : $t('mx.refresh')}</button>
  </div>

  {#if err}
    <div class="text-xs text-neon-red font-mono">{err}</div>
  {:else if loading}
    <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('mx.scanning')}</div>
  {:else if !vms.length}
    <div class="hud-panel p-6 text-center">
      <div class="hud-label mb-1">{$t('mx.empty')}</div>
    </div>
  {:else}
    <div class="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(260px,1fr))]">
      {#each vms as vm (vm.id)}
        {@const st = status(vm)}
        <button
          class="hud-panel p-3 text-left space-y-2 hover:border-neon-green/50 transition-colors"
          on:click={() => dispatch('select', { kind: 'vm', id: vm.id })}
        >
          <div class="flex items-center gap-2">
            <span class="h-2.5 w-2.5 rounded-full shrink-0 {lampClass(st)}" title={$t(verdictKey(st))}></span>
            <span class="hud-label text-hud-dim shrink-0">#{vm.display_no || vm.id}</span>
            <span class="font-mono text-sm text-emerald-100 truncate flex-1">{vm.name}</span>
            {#if vm.has_creds}<Lock size={12} cls="text-neon-amber/80 shrink-0" title={$t('vd.credsSet')} />{/if}
            {#if alertedIds.has(vm.id)}<Bell size={13} cls="text-neon-green shrink-0" title={$t('list.alertOn')} />{/if}
            {#if vm.ai_enabled}<span class="hud-label text-neon-cyan shrink-0" title={vm.ai_enabled ? $t('vd.aiOn') : $t('vd.aiOff')}>ai</span>{/if}
          </div>
          <div class="text-[11px] font-mono text-hud-dim truncate">{vm.ip || vm.hostname}{vm.port_ssh && vm.port_ssh !== 22 ? ':' + vm.port_ssh : ''}</div>
          <div class="text-xs font-mono uppercase {verdictColor(st)}">{$t(verdictKey(st))}</div>
          {#if st !== 'ok' && st !== 'unknown'}
            {@const r = reason(vm)}
            {#if r}<div class="text-[11px] font-mono text-neon-amber leading-tight line-clamp-2">{r}</div>{/if}
          {/if}
          {#if health[vm.id]?.breakdown?.length}
            <div class="flex flex-wrap gap-1 pt-1 border-t border-hud-line">
              {#each health[vm.id].breakdown as b}
                <span class="text-[10px] font-mono border rounded px-1 {b.status === 'ok' ? 'text-neon-green border-neon-green/30' : b.status === 'critical' ? 'text-neon-red border-neon-red/30' : 'text-hud-dim border-hud-line'}" title={b.check_type + ': ' + b.status + (b.message ? ' — ' + b.message : '')}>{b.check_type} {b.status === 'ok' ? '✓' : b.status === 'critical' ? '✗' : '·'}</span>
              {/each}
            </div>
          {/if}
        </button>
      {/each}
    </div>
    <div class="hud-label text-hud-dim">{$t('mx.clickHint')}</div>

    {#if domains.length}
      <div class="border-t border-hud-line pt-3 mt-2 space-y-2">
        <div class="hud-label text-neon-green">{$t('list.domains', { n: domains.length })}</div>
        <div class="grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(220px,1fr))]">
          {#each domains as d (d.id)}
            <button
              class="hud-panel p-2.5 text-left hover:border-neon-green/50 transition-colors flex items-center gap-2"
              on:click={() => dispatch('select', { kind: 'domain', id: d.id, name: d.name })}
            >
              <span class="inline-block w-2 h-2 rounded-full shrink-0 {domDotClass(domStatus(d.id))}" title={domTitle(d)}></span>
              <span class="font-mono text-sm text-emerald-100 truncate flex-1">{d.name}</span>
              <span class="hud-label text-hud-dim shrink-0">↗</span>
            </button>
          {/each}
        </div>
      </div>
    {/if}
  {/if}
</div>
