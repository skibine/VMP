<script>
  // region FleetSidebar [DOMAIN(7): UI; CONCEPT(7]: MasterList; TECH(6]: svelte]
  // Fleet sidebar: "all" overview + two collapsible groups (servers, domains). Emits 'select'
  // with null (all) or {kind:'vm'|'domain', id, name?}; 'changed' when a VM/domain is added/edited.
  import { onMount, onDestroy, createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { coverage, vmAlerted, refreshAlertCoverage } from '../lib/alerts.js'
  import { credRevision } from '../lib/stores.js'
  import AddVm from './AddVm.svelte'
  import Bell from './Bell.svelte'
  import Lock from './Lock.svelte'

  const dispatch = createEventDispatcher()

  // Selection: selKind = null (all) | 'vm' | 'domain'; selId = the entity id.
  export let selKind = null
  export let selId = null

  let vms = []
  let domains = []
  let health = {} // vm id -> status
  let domHealth = {} // domain id -> {status, reasons, dns_changed, ...}
  let loading = true
  let error = ''
  let showAddVm = false
  let showAddDom = false
  let domName = ''
  let domErr = ''
  let domBusy = false
  let serversOpen = true
  let equipOpen = true
  let domainsOpen = true

  async function refreshHealth() {
    if (!vms || !vms.length) return
    const entries = await Promise.all(
      vms.map(async (v) => {
        try {
          const h = await api.vmHealth(v.id)
          // Use the backend's worst-case status directly. A server with a critical (down) liveness
          // check is DOWN — never downgrade it to "warn" just because some other check still passes.
          return [v.id, h.status]
        } catch (_) {
          return [v.id, 'unknown']
        }
      })
    )
    health = Object.fromEntries(entries)
  }

  // Domain fleet health: reachability + registration/cert expiry + DNS-change vs baseline. Mirrors
  // the VM health polling so domain lamps track live status without a page refresh.
  async function refreshDomHealth() {
    if (!domains || !domains.length) return
    const entries = await Promise.all(
      domains.map(async (d) => {
        try {
          return [d.id, await api.domainHealth(d.id)]
        } catch (_) {
          return [d.id, { status: 'unknown', reasons: [] }]
        }
      })
    )
    domHealth = Object.fromEntries(entries)
  }

  // Liveness-alert bell state is shared (lib/alerts.js): one batch fetch, one "isCovered" rule used
  // by the sidebar, fleet matrix and VM detail alike. A transient fetch keeps last-known (no blank).
  $: alertedIds = new Set(vms.filter((v) => vmAlerted(v.id, $coverage)).map((v) => v.id))
  // Semantic split: servers vs network equipment (routers/cameras/web panels, kind != server).
  $: serverVms = vms.filter((v) => !v.kind || v.kind === 'server')
  $: equipVms = vms.filter((v) => v.kind && v.kind !== 'server')

  async function load() {
    loading = true
    error = ''
    try {
      const [v, d] = await Promise.all([api.listVms().catch(() => []), api.listDomains().catch(() => [])])
      vms = v || []
      domains = d || []
      await Promise.all([refreshHealth(), refreshDomHealth(), refreshAlertCoverage()])
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  async function addDomain() {
    domErr = ''
    domName = domName.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!domName) return
    domBusy = true
    try {
      await api.createDomain({ name: domName })
      domName = ''
      await load()
      dispatch('changed')
    } catch (e) {
      domErr = e.message
    } finally {
      domBusy = false
    }
  }

  function color(status) {
    return status === 'ok' ? 'neon-green' : status === 'warn' ? 'neon-amber' : status === 'critical' ? 'neon-red' : 'hud-dim'
  }
  // Bright LED dot (bg + matching text so the .led box-shadow halo follows the status color),
  // with a breathing pulse on any real status; "unknown" stays a static dim outline.
  function dotClass(status) {
    if (status === 'unknown') return 'border border-hud-line bg-transparent'
    return 'bg-' + color(status) + ' text-' + color(status) + ' led led-pulse'
  }
  function dotTitle(status) {
    switch (status) {
      case 'ok': return $t('list.up')
      case 'warn': return $t('list.warn')
      case 'critical': return $t('list.down')
      default: return $t('list.unknown')
    }
  }

  // Domain status helpers: same LED treatment as servers, colored by fleet health.
  function domStatus(id) { return domHealth[id]?.status ?? 'ok' }
  function domDotClass(st) {
    if (st === 'critical') return 'bg-neon-red text-neon-red led led-pulse'
    if (st === 'warn') return 'bg-neon-amber text-neon-amber led led-pulse'
    return 'bg-neon-green text-neon-green led led-pulse'
  }
  function domTitle(d) {
    const h = domHealth[d.id]
    if (h && h.reasons && h.reasons.length) return h.reasons.join('; ')
    return $t('list.up')
  }

  let healthTimer
  let credUnsub
  let onVisible
  onMount(() => {
    load()
    refreshAlertCoverage()
    healthTimer = setInterval(() => { refreshHealth(); refreshDomHealth() }, 30000)
    // Browsers throttle setInterval in background tabs, so the status would freeze until the user
    // returns and manually refreshes. Re-fetch immediately when the tab becomes visible/focused.
    onVisible = () => { if (!document.hidden) { refreshHealth(); refreshDomHealth(); refreshAlertCoverage() } }
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

<div class="h-full flex flex-col">
  <div class="flex items-center gap-2 px-3 py-2 border-b border-hud-line">
    <span class="hud-label">{$t('list.fleet', { n: vms.length ?? 0 })}</span>
  </div>

  <div class="flex-1 overflow-auto">
    {#if loading}
      <div class="px-3 py-2 hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('list.scanning')}</div>
    {:else if error}
      <div class="px-3 py-2 text-xs text-neon-red font-mono">{error}</div>
    {:else}
      <!-- "all" overview entry -->
      <button
        class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === null ? 'bg-hud-panel2 border-l-2 border-l-neon-cyan' : ''}"
        on:click={() => dispatch('select', null)}
      >
        <span class="text-neon-cyan text-sm shrink-0">▦</span>
        <span class="min-w-0">
          <span class="block font-mono text-sm {selKind === null ? 'text-neon-cyan' : 'text-emerald-100'} truncate">{$t('list.all')}</span>
          <span class="block text-[10px] text-hud-dim font-mono truncate">{$t('list.allHint', { n: vms.length })}</span>
        </span>
      </button>

      <!-- servers group (kind=server) -->
      <div class="relative">
        <button class="w-full text-left px-2 py-1.5 flex items-center gap-1 hover:bg-hud-panel2 border-b border-hud-line/60" on:click={() => (serversOpen = !serversOpen)}>
          <span class="text-[10px] text-hud-dim w-3">{serversOpen ? '▾' : '▸'}</span>
          <span class="hud-label text-neon-green">{$t('list.servers', { n: serverVms.length })}</span>
          <button class="hud-btn !px-1.5 !py-0 ml-auto !text-[10px]" on:click|stopPropagation={() => (showAddVm = !showAddVm)} title={$t('list.addVm')}>{showAddVm ? '−' : '+'}</button>
        </button>
        {#if showAddVm}
          <div class="fixed inset-0 z-[65]" on:click={() => (showAddVm = false)} on:contextmenu|preventDefault={() => (showAddVm = false)}></div>
          <div class="absolute left-2 right-2 top-full mt-1 hud-panel p-2 z-[70]">
            <AddVm on:created={() => { showAddVm = false; dispatch('changed') }} />
          </div>
        {/if}
      </div>
      {#if serversOpen}
        {#each serverVms as vm (vm.id)}
          {@const st = health[vm.id] ?? 'unknown'}
          <button
            class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === 'vm' && selId === vm.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
            on:click={() => dispatch('select', { kind: 'vm', id: vm.id })}
          >
            <span class="h-2 w-2 rounded-full shrink-0 {dotClass(st)}" title={dotTitle(st)}></span>
            <span class="hud-label text-hud-dim shrink-0">#{vm.display_no || vm.id}</span>
            <span class="min-w-0 flex-1">
              <span class="block font-mono text-sm text-emerald-100 truncate">{vm.name}</span>
              <span class="block text-[10px] text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</span>
            </span>
            {#if vm.has_creds}<Lock size={11} cls="text-neon-amber/80 shrink-0" title={$t('vd.credsSet')} />{/if}
            {#if alertedIds.has(vm.id)}<Bell size={12} cls="text-neon-green shrink-0" />{/if}
          </button>
        {/each}
        {#if !serverVms.length}<div class="px-3 py-2 hud-label text-hud-dim">{$t('list.empty')}</div>{/if}
      {/if}

      <!-- equipment group (kind=network/iot/web) -->
      {#if equipVms.length}
        <button class="w-full text-left px-2 py-1.5 flex items-center gap-1 hover:bg-hud-panel2 border-b border-hud-line/60" on:click={() => (equipOpen = !equipOpen)}>
          <span class="text-[10px] text-hud-dim w-3">{equipOpen ? '▾' : '▸'}</span>
          <span class="hud-label text-neon-amber">{$t('list.equipment', { n: equipVms.length })}</span>
        </button>
        {#if equipOpen}
          {#each equipVms as vm (vm.id)}
            {@const st = health[vm.id] ?? 'unknown'}
            <button
              class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === 'vm' && selId === vm.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
              on:click={() => dispatch('select', { kind: 'vm', id: vm.id })}
            >
              <span class="h-2 w-2 rounded-full shrink-0 {dotClass(st)}" title={dotTitle(st)}></span>
              <span class="text-[9px] font-mono px-1 rounded border border-neon-amber/40 text-neon-amber shrink-0 uppercase">{$t('vmk.equipment')}</span>
              <span class="min-w-0 flex-1">
                <span class="block font-mono text-sm text-emerald-100 truncate">{vm.name}</span>
                <span class="block text-[10px] text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</span>
              </span>
              {#if alertedIds.has(vm.id)}<Bell size={12} cls="text-neon-green shrink-0" />{/if}
            </button>
          {/each}
        {/if}
      {/if}

      <!-- domains group -->
      <button class="w-full text-left px-2 py-1.5 flex items-center gap-1 hover:bg-hud-panel2 border-b border-hud-line/60" on:click={() => (domainsOpen = !domainsOpen)}>
        <span class="text-[10px] text-hud-dim w-3">{domainsOpen ? '▾' : '▸'}</span>
        <span class="hud-label text-neon-green">{$t('list.domains', { n: domains.length })}</span>
        <button class="hud-btn !px-1.5 !py-0 ml-auto !text-[10px]" on:click|stopPropagation={() => (showAddDom = !showAddDom)} title={$t('dom.addDomain')}>{showAddDom ? '−' : '+'}</button>
      </button>
      {#if showAddDom}
        <form class="p-2 border-b border-hud-line/60 flex items-center gap-1" on:submit|preventDefault={addDomain}>
          <input class="hud-input !py-1 text-xs" placeholder="example.com" bind:value={domName} />
          <button class="hud-btn hud-btn-primary !py-1 !px-2 !text-xs" disabled={domBusy}>{domBusy ? '…' : '✓'}</button>
        </form>
        {#if domErr}<div class="px-3 pb-1 text-[11px] font-mono text-neon-red">{domErr}</div>{/if}
      {/if}
      {#if domainsOpen}
        {#each domains as d (d.id)}
          <button
            class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === 'domain' && selId === d.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
            on:click={() => dispatch('select', { kind: 'domain', id: d.id, name: d.name })}
          >
            <span class="inline-block w-2 h-2 rounded-full shrink-0 {domDotClass(domStatus(d.id))}" title={domTitle(d)}></span>
            <span class="min-w-0">
              <span class="block font-mono text-sm text-emerald-100 truncate">{d.name}</span>
              <span class="block text-[10px] text-hud-dim font-mono truncate">{$t('nav.domains')}</span>
            </span>
          </button>
        {/each}
        {#if !domains.length}<div class="px-3 py-2 hud-label text-hud-dim">{$t('dom.empty')}</div>{/if}
      {/if}
    {/if}
  </div>
</div>
