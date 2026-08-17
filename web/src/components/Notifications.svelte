<script>
  // region Notifications [DOMAIN(7): UI; CONCEPT(8]: InAppCenter; TECH(6]: svelte]
  // Bell icon + unread badge + dropdown + transient toast. The dropdown shows UNREAD
  // notifications ONLY (read ones live in the "show all" modal); fired-alert history is NOT
  // duplicated here anymore (it has its own tab in the modal). Polls every 20s; toasts the
  // newest unread when the count rises.
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import Bell from './Bell.svelte'
  import AllNotifications from './AllNotifications.svelte'
  import { portal } from '../lib/portal.js'

  let all = [] // full recent list (drives badge/toast logic)
  let items = [] // rendered: unread only
  let unread = 0
  let open = false
  let showAll = false
  let toast = null
  let toastTimer = null
  let prevUnread = 0
  let timer = null

  async function load() {
    try {
      all = (await api.listNotifications()) || []
      items = all.filter((n) => !n.read_at)
      unread = items.length
      // Toast the newest unread when count increases (a new reminder fired).
      if (unread > prevUnread && prevUnread !== 0) {
        if (items[0]) showToast(items[0])
      }
      prevUnread = unread
    } catch (_) { /* offline / logged out — ignore */ }
  }

  function showToast(n) {
    toast = n
    clearTimeout(toastTimer)
    toastTimer = setTimeout(() => (toast = null), 6000)
  }

  async function markAll() {
    try { await api.markAllNotificationsRead(); await load() } catch (_) {}
  }
  async function markOne(id) {
    try { await api.markNotificationRead(id); await load() } catch (_) {}
  }

  onMount(() => { load(); timer = setInterval(load, 20000) })
  onDestroy(() => { clearInterval(timer); clearTimeout(toastTimer) })
</script>

<div class="relative">
  <button class="hud-btn !px-2 relative" on:click={() => (open = !open)} title={$t('nt.title')} aria-label={$t('nt.title')}>
    <Bell size={16} cls="text-neon-cyan" />
    {#if unread > 0}
      <span class="absolute -top-1 -right-1 bg-neon-red text-white text-[9px] font-mono rounded-full min-w-[15px] h-[15px] flex items-center justify-center px-0.5">{unread}</span>
    {/if}
  </button>

  {#if open}
    <div class="absolute right-0 mt-2 w-80 hud-panel !bg-hud-panel p-0 z-[70] max-h-96 overflow-auto">
      <div class="flex items-center justify-between gap-1 px-3 py-2 border-b border-hud-line sticky top-0 !bg-hud-panel">
        <span class="hud-label text-neon-cyan truncate">{$t('nt.title')}</span>
        <div class="flex items-center gap-1 shrink-0">
          {#if unread > 0}
            <button class="hud-btn !py-0.5 !px-1.5 !text-[11px]" on:click={markAll} title={$t('nt.markAll')}>✓✓</button>
          {/if}
          <button class="hud-btn !py-0.5 !px-1.5 !text-[11px] text-neon-cyan"
            on:click={() => { open = false; showAll = true }}
            title={$t('nt.showAll')}>☰ →</button>
        </div>
      </div>
      {#if !items.length}
        <div class="px-3 py-4 hud-label text-hud-dim">{$t('nt.emptyUnread')}</div>
      {:else}
        {#each items as n (n.id)}
          <button class="block w-full text-left px-3 py-2 border-b border-hud-line/60 hover:bg-hud-panel2" on:click={() => markOne(n.id)}>
            <div class="text-xs font-mono text-neon-green flex items-center gap-1">
              <span class="h-1.5 w-1.5 rounded-full bg-neon-green shrink-0"></span>
              <span class="truncate">{n.title}</span>
            </div>
            <div class="text-[11px] text-hud-dim font-mono mt-0.5 break-words">{n.body}</div>
            <div class="text-[10px] text-hud-dim/70 font-mono mt-0.5">{n.created_at?.slice(0, 19).replace('T', ' ')}</div>
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>

{#if showAll}
  <AllNotifications on:close={() => { showAll = false; load() }} on:refresh={load} />
{/if}

{#if toast}
  <div use:portal class="fixed bottom-4 right-4 z-[60] hud-panel !bg-hud-panel p-3 max-w-sm border-neon-green/40 animate-pulse-once">
    <div class="text-xs font-mono text-neon-green flex items-center gap-1">
      <Bell size={14} cls="text-neon-green" /><span class="truncate">{toast.title}</span>
    </div>
    <div class="text-[11px] text-hud-dim font-mono mt-1 break-words">{toast.body}</div>
  </div>
{/if}

<svelte:window on:click={(e) => { if (open && !e.target.closest('.relative')) open = false }} />
