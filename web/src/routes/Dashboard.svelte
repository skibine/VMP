<script>
  import { api } from '../lib/api.js'
  import { user, logout as doLogout } from '../lib/stores.js'
  import VmList from '../components/VmList.svelte'
  import ChatPanel from '../components/ChatPanel.svelte'

  async function logout() {
    await api.logout()
    doLogout()
  }
</script>

<div class="min-h-full flex flex-col">
  <!-- Top bar -->
  <header class="hud-panel border-x-0 border-t-0 px-4 py-2 flex items-center gap-4">
    <div class="hud-label">// VM&nbsp;PULSE</div>
    <div class="hud-label text-neon-green/70">control&nbsp;plane</div>
    <div class="ml-auto flex items-center gap-4">
      <span class="hud-label">user:&nbsp;{$user?.username ?? '—'}</span>
      <button class="hud-btn" on:click={logout}>logout</button>
    </div>
  </header>

  <!-- Split layout: content + always-visible chat -->
  <main class="flex-1 grid grid-cols-[1fr_380px] min-h-0">
    <section class="overflow-auto hud-grid p-4">
      <VmList />
    </section>
    <aside class="hud-panel border-y-0 border-r-0 min-h-0">
      <ChatPanel />
    </aside>
  </main>
</div>
