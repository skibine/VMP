<script>
  import { onMount, createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
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

  async function load() {
    loading = true
    error = ''
    try {
      vms = await api.listVms()
      const entries = await Promise.all(
        (vms || []).map(async (v) => {
          try {
            const h = await api.vmHealth(v.id)
            // Derive a liveness-ish state: green=all ok; amber=some service down BUT at least one
            // check ok (box reachable, a service failing); red=NO check ok (likely down); dim=unknown.
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
      if (selectedId === null && vms.length) {
        dispatch('select', vms[0].id)
      }
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

  onMount(load)
</script>

<div class="h-full flex flex-col">
  <div class="flex items-center gap-2 px-3 py-2 border-b border-hud-line">
    <span class="hud-label">fleet&nbsp;//&nbsp;{vms.length ?? 0}</span>
    <button class="hud-btn ml-auto !px-2 !py-1" on:click={() => (showAdd = !showAdd)}>
      {showAdd ? '✕' : '+ vm'}
    </button>
  </div>

  {#if showAdd}
    <div class="p-3 border-b border-hud-line">
      <AddVm on:created={() => { showAdd = false; load() }} />
    </div>
  {/if}

  <div class="flex-1 overflow-auto">
    {#if loading}
      <div class="px-3 py-2 hud-label animate-pulse">scanning…</div>
    {:else if error}
      <div class="px-3 py-2 text-xs text-neon-red font-mono">{error}</div>
    {:else if !vms.length}
      <div class="px-3 py-4 hud-label">no vms — add one</div>
    {:else}
      {#each vms as vm (vm.id)}
        {@const st = health[vm.id] ?? 'unknown'}
        <button
          class="w-full text-left px-3 py-2 border-b border-hud-line/60 flex items-center gap-2 hover:bg-hud-panel2 transition-colors {selectedId === vm.id ? 'bg-hud-panel2 border-l-2 border-l-neon-green' : ''}"
          on:click={() => dispatch('select', vm.id)}
        >
          <span class="h-2 w-2 rounded-full bg-{color(st)} shrink-0"></span>
          <span class="hud-label text-hud-dim shrink-0">#{vm.display_no || vm.id}</span>
          <span class="min-w-0">
            <span class="block font-mono text-sm text-emerald-100 truncate">{vm.name}</span>
            <span class="block text-[10px] text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</span>
          </span>
        </button>
      {/each}
    {/if}
  </div>
</div>
