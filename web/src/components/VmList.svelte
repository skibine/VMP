<script>
  import { onMount, onDestroy, createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import AddVm from './AddVm.svelte'

  // region VmList [DOMAIN(7): UI; CONCEPT(7]: MasterList; TECH(6]: svelte]
  // Compact, scalable VM list (master). Emits 'select' with the vm id; 'add' handled inline.
  const dispatch = createEventDispatcher()

  export let selectedId = null

  let vms = []
  let health = {} // id -> status
  let loading = true
  let error = ''
  let showAdd = false

  // refreshHealth re-fetches only the liveness status for the currently-known VMs. The engine
  // writes fresh check results every ~60s; without polling this map the sidebar lamps freeze at
  // their mount-time value (a newly-added VM stays grey until a manual page refresh).
  async function refreshHealth() {
    if (!vms || !vms.length) return
    const entries = await Promise.all(
      vms.map(async (v) => {
        try {
          const h = await api.vmHealth(v.id)
          // green=all ok; amber=some service down BUT at least one check ok (box reachable);
          // red=NO check ok (likely down); dim=unknown.
          const anyOk = (h.breakdown || []).some((b) => b.status === 'ok')
          let st = h.status
          if (st === 'critical' && anyOk) st = 'warn' // reachable but degraded -> amber, not red
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
      vms = await api.listVms()
      await refreshHealth()
      // Default selection is "all" (null) -> the main area shows the fleet matrix overview.
      // A specific VM is selected by clicking it; no auto-drill-into the first VM.
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  function color(status) {
    return status === 'ok'
      ? 'neon-green'
      : status === 'warn'
        ? 'neon-amber'
        : status === 'critical'
          ? 'neon-red'
          : 'hud-dim'
  }

  // unknown (no/pending checks) renders as a VISIBLE hollow ring, not an invisible grey blob.
  function dotClass(status) {
    return status === 'unknown'
      ? 'border border-hud-line bg-transparent'
      : 'bg-' + color(status)
  }
  function dotTitle(status) {
    switch (status) {
      case 'ok': return $t('list.up')
      case 'warn': return $t('list.warn')
      case 'critical': return $t('list.down')
      default: return $t('list.unknown')
    }
  }

  // Poll health every 30s so lamps reflect the latest check results without a page refresh.
  // (The engine refreshes liveness ~every 60s; this keeps the UI within one poll of reality.)
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
    <button class="hud-btn ml-auto !px-2 !py-1" on:click={() => (showAdd = !showAdd)}>
      {showAdd ? '✕' : $t('list.addVm')}
    </button>
  </div>

  {#if showAdd}
    <div class="p-3 border-b border-hud-line">
      <AddVm on:created={() => { showAdd = false; dispatch('changed') }} />
    </div>
  {/if}

  <div class="flex-1 overflow-auto">
    {#if loading}
      <div class="px-3 py-2 hud-label animate-pulse">{$t('list.scanning')}</div>
    {:else if error}
      <div class="px-3 py-2 text-xs text-neon-red font-mono">{error}</div>
    {:else}
      <!-- "all" overview entry: shows the fleet matrix in the main area. Default selection. -->
      <button
        class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selectedId === null ? 'bg-hud-panel2 border-l-2 border-l-neon-cyan' : ''}"
        on:click={() => dispatch('select', null)}
      >
        <span class="text-neon-cyan text-sm shrink-0">▦</span>
        <span class="min-w-0">
          <span class="block font-mono text-sm {selectedId === null ? 'text-neon-cyan' : 'text-emerald-100'} truncate">{$t('list.all')}</span>
          <span class="block text-[10px] text-hud-dim font-mono truncate">{$t('list.allHint', { n: vms.length })}</span>
        </span>
      </button>
      {#if !vms.length}
        <div class="px-3 py-4 hud-label">{$t('list.empty')}</div>
      {:else}
        {#each vms as vm (vm.id)}
          {@const st = health[vm.id] ?? 'unknown'}
          <button
            class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selectedId === vm.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
            on:click={() => dispatch('select', vm.id)}
          >
            <span class="h-2 w-2 rounded-full shrink-0 {dotClass(st)}" title={dotTitle(st)}></span>
            <span class="hud-label text-hud-dim shrink-0">#{vm.display_no || vm.id}</span>
            <span class="min-w-0">
              <span class="block font-mono text-sm text-emerald-100 truncate">{vm.name}</span>
              <span class="block text-[10px] text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</span>
            </span>
          </button>
        {/each}
      {/if}
    {/if}
  </div>
</div>
