<script>
  // region FleetMatrix [DOMAIN(7): UI; CONCEPT(8]: FleetOverview; TECH(6]: svelte]
  // Default landing: a responsive auto-fill grid of identical VM cards. Each card shows the
  // liveness lamp (green/amber/red/hollow) from stored check results (no live probe load on the
  // grid) + the per-check verdict chips. Click a card -> drill into the master-detail.
  // Pairs with the future "security // exposures" signal (a card badge) — no-root intel only.
  import { createEventDispatcher, onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  const dispatch = createEventDispatcher()

  let vms = []
  let domains = []
  let health = {} // id -> {status, breakdown:[{check_type,status}]}
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

  async function load() {
    loading = true
    err = ''
    try {
      vms = await api.listVms()
      domains = (await api.listDomains().catch(() => [])) || []
      await refreshHealth()
    } catch (e) {
      err = e.message
    } finally {
      loading = false
    }
  }

  // Mirror VmList semantics: critical-but-something-ok => amber (reachable, a service failing).
  function status(v) {
    let st = health[v.id]?.status || 'unknown'
    const anyOk = (health[v.id]?.breakdown || []).some((b) => b.status === 'ok')
    if (st === 'critical' && anyOk) st = 'warn'
    return st
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
    return st === 'ok'
      ? 'bg-neon-green'
      : st === 'warn'
        ? 'bg-neon-amber'
        : st === 'critical'
          ? 'bg-neon-red'
          : 'border border-hud-line bg-transparent'
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
  async function scanAllSecurity() {
    if (scanning) return
    scanning = true
    try {
      await api.exposuresScanAll()
      await refreshHealth()
    } catch (_) { /* surface via toast later */ }
    scanning = false
  }
  onMount(() => {
    load()
    healthTimer = setInterval(refreshHealth, 30000)
  })
  onDestroy(() => clearInterval(healthTimer))
</script>

<div class="h-full overflow-auto p-4 space-y-4">
  <div class="flex items-center gap-2">
    <h2 class="font-mono text-neon-green text-lg">{$t('mx.title', { n: vms.length ?? 0 })}</h2>
    <button class="hud-btn !py-0.5" on:click={scanAllSecurity} disabled={scanning} title={$t('mx.scanAllHint')}>{scanning ? '…' : $t('mx.scanAll')}</button>
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
        <div class="hud-label text-neon-amber">{$t('list.domains', { n: domains.length })}</div>
        <div class="grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(220px,1fr))]">
          {#each domains as d (d.id)}
            <button
              class="hud-panel p-2.5 text-left hover:border-neon-amber/50 transition-colors flex items-center gap-2"
              on:click={() => dispatch('select', { kind: 'domain', id: d.id, name: d.name })}
            >
              <span class="inline-block w-2 h-2 rounded-full shrink-0 bg-neon-amber/70"></span>
              <span class="font-mono text-sm text-emerald-100 truncate flex-1">{d.name}</span>
              <span class="hud-label text-hud-dim shrink-0">↗</span>
            </button>
          {/each}
        </div>
      </div>
    {/if}
  {/if}
</div>
