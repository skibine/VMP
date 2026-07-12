<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import HealthBadge from './HealthBadge.svelte'
  import AddVm from './AddVm.svelte'

  let vms = []
  let health = {} // id -> {status, score}
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
            return [v.id, { status: h.status, score: h.score }]
          } catch (_) {
            return [v.id, { status: 'unknown', score: null }]
          }
        })
      )
      health = Object.fromEntries(entries)
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  onMount(load)
</script>

<div class="space-y-4">
  <div class="flex items-center gap-3">
    <h2 class="hud-label">fleet&nbsp;//&nbsp;{vms.length ?? 0}&nbsp;vm</h2>
    <button class="hud-btn ml-auto" on:click={() => (showAdd = !showAdd)}>
      {showAdd ? 'close' : '+ add vm'}
    </button>
  </div>

  {#if showAdd}
    <div class="hud-panel p-4">
      <AddVm on:created={() => { showAdd = false; load() }} />
    </div>
  {/if}

  {#if loading}
    <div class="hud-label animate-pulse">scanning fleet…</div>
  {:else if error}
    <div class="text-xs text-neon-red font-mono">{error}</div>
  {:else if !vms.length}
    <div class="hud-panel p-6 text-center">
      <div class="hud-label mb-2">no vms registered</div>
      <p class="text-xs text-hud-dim">Add your first VM to start monitoring.</p>
    </div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
      {#each vms as vm (vm.id)}
        {@const h = health[vm.id] ?? { status: 'unknown', score: null }}
        <div class="hud-panel scan p-4 space-y-3 hover:border-neon-green/40 transition-colors">
          <div class="flex items-start gap-2">
            <div class="min-w-0">
              <div class="font-mono text-neon-green truncate">{vm.name}</div>
              <div class="text-xs text-hud-dim font-mono truncate">{vm.ip || vm.hostname}</div>
            </div>
          </div>
          <HealthBadge status={h.status} score={h.score} />
          {#if vm.tags?.length}
            <div class="flex flex-wrap gap-1">
              {#each vm.tags as t}
                <span class="hud-label border border-hud-line rounded px-1.5 py-0.5">{t}</span>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
