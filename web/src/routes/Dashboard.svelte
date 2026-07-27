<script>
  import { api } from '../lib/api.js'
  import { user, logout as doLogout, themeLight, toggleTheme } from '../lib/stores.js'
  import { t, setLocale, locale } from '../lib/i18n.js'
  import VmList from '../components/VmList.svelte'
  import VmDetail from '../components/VmDetail.svelte'
  import FleetMatrix from '../components/FleetMatrix.svelte'
  import ChatPanel from '../components/ChatPanel.svelte'
  import Domains from '../components/Domains.svelte'
  import Alerts from '../components/Alerts.svelte'
  import Settings from './Settings.svelte'

  let view = 'fleet' // 'fleet' | 'domains' | 'alerts' | 'settings'
  let selectedId = null // null = "all" (fleet matrix overview); <id> = master-detail drill-in

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

  // Resizable chat column: drag the handle between the info pane and the chat to widen/narrow it.
  // Persisted to localStorage so the operator's preferred width survives reloads.
  let chatW = Number(localStorage.getItem('vmp_chat_w') || 360)
  const CHAT_MIN = 300
  const CHAT_MAX = 760
  let dragging = false

  function startDrag(e) {
    e.preventDefault()
    dragging = true
  }
  function onMove(e) {
    if (!dragging) return
    // chat is on the right edge -> its width = viewport right minus pointer X (clamped).
    const w = Math.min(CHAT_MAX, Math.max(CHAT_MIN, window.innerWidth - e.clientX))
    chatW = w
    localStorage.setItem('vmp_chat_w', String(w))
  }
  function stopDrag() {
    if (dragging) {
      dragging = false
      localStorage.setItem('vmp_chat_w', String(chatW))
    }
  }
</script>

<svelte:window on:mousemove={onMove} on:mouseup={stopDrag} />

<div class="h-full flex flex-col overflow-hidden">
  <!-- Top bar -->
  <header class="hud-panel border-x-0 border-t-0 px-4 py-2 flex items-center gap-4 shrink-0">
    <div class="hud-label">// VM&nbsp;PULSE</div>
    <div class="flex items-center gap-1">
      <button class="hud-btn {view === 'fleet' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'fleet')}>{$t('nav.fleet')}</button>
      <button class="hud-btn {view === 'domains' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'domains')}>{$t('nav.domains')}</button>
      <button class="hud-btn {view === 'alerts' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'alerts')}>{$t('nav.alerts')}</button>
      <button class="hud-btn {view === 'settings' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'settings')}>{$t('nav.settings')}</button>
    </div>
    <div class="ml-auto flex items-center gap-4">
      <button class="hud-btn" on:click={() => setLocale($locale === 'ru' ? 'en' : 'ru')} title="switch language">{$t('nav.lang')}</button>
      <button class="hud-btn" on:click={toggleTheme} title="toggle light/dark theme">{$themeLight ? $t('nav.themeDark') : $t('nav.themeLight')}</button>
      <span class="hud-label">{$t('nav.user')}&nbsp;{$user?.username ?? '—'}</span>
      <button class="hud-btn" on:click={logout}>{$t('nav.logout')}</button>
    </div>
  </header>

  {#if view === 'fleet'}
    <!-- master (sidebar, always visible) + detail/matrix + chat (resizable).
         "all" in the sidebar (selectedId === null) shows the fleet matrix grid; a specific VM
         shows its detail. The sidebar never disappears. -->
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="hud-panel border-l-0 border-y-0 min-h-0 overflow-auto shrink-0" style="width:220px">
        <!-- BUG_FIX_CONTEXT: `key={listKey}` as a component ATTRIBUTE is a no-op prop in Svelte, NOT a
             remount directive — only a {#key} BLOCK remounts. Without the block the always-mounted
             sidebar never reloaded after add/delete/edit (stale until F5). -->
        {#key listKey}
          <VmList {selectedId} on:select={onSelect} on:changed={onVmChanged} />
        {/key}
      </section>
      <section class="overflow-auto hud-grid min-h-0 flex-1">
        {#if selectedId === null}
          {#key listKey}
            <FleetMatrix on:select={onSelect} on:changed={onVmChanged} />
          {/key}
        {:else}
          <VmDetail vmId={selectedId} on:changed={onVmChanged} on:deleted={onVmDeleted} />
        {/if}
      </section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator"
        aria-orientation="vertical"
        on:mousedown={startDrag}
        title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px">
        <ChatPanel />
      </aside>
    </main>
  {:else if view === 'domains'}
    <!-- domains + chat (resizable) -->
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="overflow-auto hud-grid min-h-0 flex-1">
        <Domains />
      </section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator"
        aria-orientation="vertical"
        on:mousedown={startDrag}
        title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px">
        <ChatPanel />
      </aside>
    </main>
  {:else if view === 'alerts'}
    <!-- alerts + chat (resizable) -->
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="overflow-auto hud-grid min-h-0 flex-1">
        <Alerts />
      </section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator"
        aria-orientation="vertical"
        on:mousedown={startDrag}
        title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px">
        <ChatPanel />
      </aside>
    </main>
  {:else}
    <!-- settings + chat (resizable) -->
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="overflow-auto hud-grid p-4 flex-1">
        <Settings />
      </section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator"
        aria-orientation="vertical"
        on:mousedown={startDrag}
        title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px">
        <ChatPanel />
      </aside>
    </main>
  {/if}
</div>
