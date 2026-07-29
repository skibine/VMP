<script>
  // region FleetSidebar [DOMAIN(7): UI; CONCEPT(7]: MasterList; TECH(6]: svelte]
  // Fleet sidebar: "all" overview + two collapsible groups (servers, domains). Emits 'select'
  // with null (all) or {kind:'vm'|'domain', id, name?}; 'changed' when a VM/domain is added/edited.
  import { onMount, onDestroy, createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import AddVm from './AddVm.svelte'

  const dispatch = createEventDispatcher()

  // Selection: selKind = null (all) | 'vm' | 'domain'; selId = the entity id.
  export let selKind = null
  export let selId = null

  let vms = []
  let domains = []
  let health = {} // vm id -> status
  let loading = true
  let error = ''
  let showAddVm = false
  let showAddDom = false
  let domName = ''
  let domErr = ''
  let domBusy = false
  let serversOpen = true
  let domainsOpen = true

  async function refreshHealth() {
    if (!vms || !vms.length) return
    const entries = await Promise.all(
      vms.map(async (v) => {
        try {
          const h = await api.vmHealth(v.id)
          const anyOk = (h.breakdown || []).some((b) => b.status === 'ok')
          let st = h.status
          if (st === 'critical' && anyOk) st = 'warn'
          return [v.id, st]
        } catch (_) {
          return [v.id, 'unknown']
        }
      })
    )
    health = Object.fromEntries(entries)
  }

  async function load() {
    loading = true
    error = ''
    try {
      const [v, d] = await Promise.all([api.listVms().catch(() => []), api.listDomains().catch(() => [])])
      vms = v || []
      domains = d || []
      await refreshHealth()
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
  function dotClass(status) {
    return status === 'unknown' ? 'border border-hud-line bg-transparent' : 'bg-' + color(status)
  }
  function dotTitle(status) {
    switch (status) {
      case 'ok': return $t('list.up')
      case 'warn': return $t('list.warn')
      case 'critical': return $t('list.down')
      default: return $t('list.unknown')
    }
  }

  let healthTimer
  onMount(() => {
    load()
    healthTimer = setInterval(refreshHealth, 30000)
  })
  onDestroy(() => clearInterval(healthTimer))
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

      <!-- servers group -->
      <button class="w-full text-left px-2 py-1.5 flex items-center gap-1 hover:bg-hud-panel2 border-b border-hud-line/60" on:click={() => (serversOpen = !serversOpen)}>
        <span class="text-[10px] text-hud-dim w-3">{serversOpen ? '▾' : '▸'}</span>
        <span class="hud-label text-neon-green">{$t('list.servers', { n: vms.length })}</span>
        <button class="hud-btn !px-1.5 !py-0 ml-auto !text-[10px]" on:click|stopPropagation={() => (showAddVm = !showAddVm)} title={$t('list.addVm')}>+</button>
      </button>
      {#if showAddVm}
        <div class="p-2 border-b border-hud-line/60">
          <AddVm on:created={() => { showAddVm = false; dispatch('changed') }} />
        </div>
      {/if}
      {#if serversOpen}
        {#each vms as vm (vm.id)}
          {@const st = health[vm.id] ?? 'unknown'}
          <button
            class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === 'vm' && selId === vm.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
            on:click={() => dispatch('select', { kind: 'vm', id: vm.id })}
          >
            <span class="h-2 w-2 rounded-full shrink-0 {dotClass(st)}" title={dotTitle(st)}></span>
            <span class="hud-label text-hud-dim shrink-0">#{vm.display_no || vm.id}</span>
            <span class="min-w-0">
              <span class="block font-mono text-sm text-emerald-100 truncate">{vm.name}</span>
              <span class="block text-[10px] text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</span>
            </span>
          </button>
        {/each}
        {#if !vms.length}<div class="px-3 py-2 hud-label text-hud-dim">{$t('list.empty')}</div>{/if}
      {/if}

      <!-- domains group -->
      <button class="w-full text-left px-2 py-1.5 flex items-center gap-1 hover:bg-hud-panel2 border-b border-hud-line/60" on:click={() => (domainsOpen = !domainsOpen)}>
        <span class="text-[10px] text-hud-dim w-3">{domainsOpen ? '▾' : '▸'}</span>
        <span class="hud-label text-neon-amber">{$t('list.domains', { n: domains.length })}</span>
        <button class="hud-btn !px-1.5 !py-0 ml-auto !text-[10px]" on:click|stopPropagation={() => (showAddDom = !showAddDom)} title={$t('dom.add')}>+</button>
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
            class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selKind === 'domain' && selId === d.id ? 'bg-hud-panel2 border-l-2 border-l-neon-amber' : ''}"
            on:click={() => dispatch('select', { kind: 'domain', id: d.id, name: d.name })}
          >
            <span class="inline-block w-2 h-2 rounded-full shrink-0 bg-neon-amber/70"></span>
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
