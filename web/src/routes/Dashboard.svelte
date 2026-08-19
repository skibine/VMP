<script>
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { user, logout as doLogout, themeLight, toggleTheme, gotoSettings, appVersion } from '../lib/stores.js'
  import { t, setLocale, locale, initLocaleFromServer } from '../lib/i18n.js'
  import VmList from '../components/VmList.svelte'
  import VmDetail from '../components/VmDetail.svelte'
  import DomainDetail from '../components/DomainDetail.svelte'
  import FleetMatrix from '../components/FleetMatrix.svelte'
  import Notifications from '../components/Notifications.svelte'
  import ChatPanel from '../components/ChatPanel.svelte'
  import Settings from './Settings.svelte'
  import Events from './Events.svelte'

  // View survives a refresh: restore from localStorage, validated against the allowed set
  // (a stale/garbage value collapses to fleet, never to a broken view).
  const VIEWS = ['fleet', 'events', 'settings']
  let view = localStorage.getItem('vmp.view')
  if (!VIEWS.includes(view)) view = 'fleet' // 'fleet' | 'events' | 'settings'
  // BUG_FIX_CONTEXT: this reactive write MUST stay at the component top level - inside a
  // callback (onMount) `$:` degrades to a plain JS label and runs once, never persisting.
  $: if (VIEWS.includes(view)) localStorage.setItem('vmp.view', view)
  // Unified selection: null = fleet overview; 'vm' = a VM; 'domain' = a domain.
  let selKind = null
  let selId = null
  let selName = ''

  // Refresh the sidebar/matrix when a VM or domain is edited/added/archived/deleted.
  let listKey = 0
  function onVmChanged() { listKey++ }
  function onSelect(e) {
    const s = e.detail
    if (s == null) { selKind = null; selId = null; selName = '' }
    else { selKind = s.kind; selId = s.id; selName = s.name || '' }
  }
  function onVmDeleted() { selKind = null; selId = null; listKey++ }
  function onDomainChanged() { selKind = null; selId = null; listKey++ }

  async function logout() {
    await api.logout()
    doLogout()
  }

  // Resizable chat column: drag the handle between the info pane and the chat to widen/narrow it.
  let chatW = Number(localStorage.getItem('vmp_chat_w') || 360)
  const CHAT_MIN = 300
  const CHAT_MAX = 760
  let dragging = false
  function startDrag(e) { e.preventDefault(); dragging = true }
  function onMove(e) {
    if (!dragging) return
    chatW = Math.min(CHAT_MAX, Math.max(CHAT_MIN, window.innerWidth - e.clientX))
    localStorage.setItem('vmp_chat_w', String(chatW))
  }
  function stopDrag() { if (dragging) { dragging = false; localStorage.setItem('vmp_chat_w', String(chatW)) } }

  let gotoUnsub
  // Security banner: server-mode instance with PLAINTEXT secrets (vault unarmed) - the
  // operator must not forget the SQLite file (and its .bak) is fully readable if stolen.
  let secWarn = false
  onMount(async () => {
    try {
      const st = await api.securityStatus()
      secWarn = st && st.mode === 'server' && st.vault_armed === false
    } catch (_) {}
  })

  onMount(() => {
    initLocaleFromServer()
    api.version().then((v) => { if (v && v.version) appVersion.set(v.version) }).catch(() => {})
    gotoUnsub = gotoSettings.subscribe((v) => { if (v) { view = 'settings'; gotoSettings.set(false) } })
  })
  onDestroy(() => gotoUnsub && gotoUnsub())
</script>

<svelte:window on:mousemove={onMove} on:mouseup={stopDrag} />

<div class="h-full flex flex-col overflow-hidden">
  {#if secWarn}
    <div class="hud-panel border-x-0 border-t-0 border-neon-amber/50 px-4 py-1.5 flex items-center gap-2 shrink-0 bg-neon-amber/5">
      <span class="hud-label text-neon-amber shrink-0">// {$t('sec.banner')}</span>
      <span class="text-[11px] text-hud-dim truncate">{$t('sec.bannerHint')}</span>
    </div>
  {/if}
  <header class="hud-panel border-x-0 border-t-0 px-4 py-2 flex items-center gap-4 shrink-0 relative z-10">
    <div class="flex items-center gap-2 shrink-0">
      <img src="/logo.png" alt="VM Pulse" class="h-6 w-6" />
      <div class="hud-label">// VM&nbsp;PULSE{#if $appVersion}<span class="text-hud-dim/70 ml-2 text-[10px] normal-case">{$appVersion}</span>{/if}</div>
    </div>
    <div class="flex items-center gap-1">
      <button class="hud-btn {view === 'fleet' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'fleet')}>{$t('nav.fleet')}</button>
      <button class="hud-btn {view === 'events' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'events')}>{$t('nav.events')}</button>
      <button class="hud-btn {view === 'settings' ? 'hud-btn-primary' : ''}" on:click={() => (view = 'settings')}>{$t('nav.settings')}</button>
    </div>
    <div class="ml-auto flex items-center gap-4">
      <Notifications />
      <button class="hud-btn" on:click={() => setLocale($locale === 'ru' ? 'en' : 'ru')} title="switch language">{$t('nav.lang')}</button>
      <button class="hud-btn" on:click={toggleTheme} title="toggle light/dark theme">{$themeLight ? $t('nav.themeDark') : $t('nav.themeLight')}</button>
      <span class="hud-label">{$t('nav.user')}&nbsp;{$user?.username ?? '—'}</span>
      <button class="hud-btn" on:click={logout}>{$t('nav.logout')}</button>
    </div>
  </header>

  {#if view === 'fleet'}
    <!-- master (sidebar: all + servers + domains groups) + detail/overview + chat (resizable) -->
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="hud-panel border-l-0 border-y-0 min-h-0 overflow-auto shrink-0" style="width:220px">
        {#key listKey}
          <VmList {selKind} {selId} on:select={onSelect} on:changed={onVmChanged} />
        {/key}
      </section>
      <section class="overflow-auto hud-grid min-h-0 flex-1">
        {#if selKind === null}
          {#key listKey}
            <FleetMatrix on:select={onSelect} on:changed={onVmChanged} />
          {/key}
        {:else if selKind === 'vm'}
          <VmDetail vmId={selId} on:changed={onVmChanged} on:deleted={onVmDeleted} />
        {:else if selKind === 'domain'}
          <DomainDetail domainId={selId} domainName={selName} on:changed={onDomainChanged} />
        {/if}
      </section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator" aria-orientation="vertical" on:mousedown={startDrag} title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px">
        <ChatPanel />
      </aside>
    </main>
  {:else if view === 'events'}
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="overflow-auto hud-grid flex-1"><Events /></section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator" aria-orientation="vertical" on:mousedown={startDrag} title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px"><ChatPanel /></aside>
    </main>
  {:else}
    <main class="flex-1 flex min-h-0 overflow-hidden">
      <section class="overflow-auto hud-grid p-4 flex-1"><Settings /></section>
      <div
        class="w-1 shrink-0 cursor-col-resize bg-hud-line/60 hover:bg-neon-cyan/50 transition-colors {dragging ? 'bg-neon-cyan/70' : ''}"
        role="separator" aria-orientation="vertical" on:mousedown={startDrag} title="drag to resize chat"
      ></div>
      <aside class="hud-panel border-y-0 border-r-0 min-h-0 overflow-hidden shrink-0" style="width:{chatW}px"><ChatPanel /></aside>
    </main>
  {/if}
</div>
