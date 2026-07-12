<script>
  import { api } from '../lib/api.js'
  import { user, logout as doLogout } from '../lib/stores.js'
  import VmList from '../components/VmList.svelte'
  import VmDetail from '../components/VmDetail.svelte'
  import ChatPanel from '../components/ChatPanel.svelte'
  import Domains from '../components/Domains.svelte'
  import Settings from './Settings.svelte'

  let view = 'fleet' // 'fleet' | 'domains' | 'settings'
  let selectedId = null

  // Refresh the list when a VM is edited/added/archived (so names/health update).
  let listKey = 0
  function onVmChanged() {
    listKey++
  }
  function onSelect(e) {
    selectedId = e.detail
  }
  function onVmDeleted() {
    selectedId = null
    listKey++
  }

  async function logout() {
    await api.logout()
    doLogout()
  }
</script>

<div class="min-h-full flex flex-col">
  <!-- Top bar -->
  <header class="hud-panel border-x-0 border-t-0 px-4 py-2 flex items-center gap-4">
    <div class="hud-label">// VM&nbsp;PULSE</div>
    <div class="flex items-center gap-1">
      <button class="hud-btn {view === 'fleet' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'fleet')}>fleet</button>
      <button class="hud-btn {view === 'domains' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'domains')}>domains</button>
      <button class="hud-btn {view === 'settings' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'settings')}>settings</button>
    </div>
    <div class="ml-auto flex items-center gap-4">
      <span class="hud-label">user:&nbsp;{$user?.username ?? '—'}</span>
      <button class="hud-btn" on:click={logout}>logout</button>
    </div>
  </header>

  {#if view === 'fleet'}
    <!-- master-detail + chat -->
    <main class="flex-1 grid grid-cols-[220px_1fr_360px] min-h-0">
      <section class="hud-panel border-l-0 border-y-0 min-h-0">
        <VmList {selectedId} on:select={onSelect} on:changed={onVmChanged} key={listKey} />
      </section>
      <section class="overflow-auto hud-grid min-h-0">
        <VmDetail vmId={selectedId} on:changed={onVmChanged} on:deleted={onVmDeleted} />
      </section>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0">
        <ChatPanel />
      </aside>
    </main>
  {:else if view === 'domains'}
    <!-- domains + chat -->
    <main class="flex-1 grid grid-cols-[1fr_360px] min-h-0">
      <section class="overflow-auto hud-grid min-h-0">
        <Domains />
      </section>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0">
        <ChatPanel />
      </aside>
    </main>
  {:else}
    <!-- settings + chat -->
    <main class="flex-1 grid grid-cols-[1fr_360px] min-h-0">
      <section class="overflow-auto hud-grid p-4">
        <Settings />
      </section>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0">
        <ChatPanel />
      </aside>
    </main>
  {/if}
</div>
