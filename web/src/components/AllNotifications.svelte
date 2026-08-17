<script>
  // region AllNotifications [DOMAIN(7): UI; CONCEPT(8): NotificationsModal; TECH(6): svelte]
  // Full history of the bell's NOTIFICATIONS (reminders / channel tests) — a modal launched from
  // the bell popup. Fired alerts are NOT here: they are events, see the events page.
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { portal } from '../lib/portal.js'

  const dispatch = createEventDispatcher()

  let items = []
  let total = 0
  let page = 1
  const size = 30
  let kind = ''
  let unread = false
  let busy = false

  async function load() {
    busy = true
    try {
      const res = await api.notificationsAll({
        page, page_size: size,
        kind: kind || '',
        unread: unread ? '1' : '',
      })
      items = res.items || []
      total = res.total || 0
    } catch (_) {} finally { busy = false }
  }

  async function markRead(id) {
    try { await api.markNotificationRead(id); await load(); dispatch('refresh') } catch (_) {}
  }

  async function clearRead() {
    if (!confirm($t('nt.confirmClearRead'))) return
    try { await api.clearNotifications('read'); page = 1; await load(); dispatch('refresh') } catch (_) {}
  }
  async function clearAll() {
    if (!confirm($t('nt.confirmClearAll'))) return
    try { await api.clearNotifications('all'); page = 1; await load(); dispatch('refresh') } catch (_) {}
  }

  function pages() { return Math.max(1, Math.ceil(total / size)) }

  load()
</script>

<!-- use:portal: fixed overlays must escape the header's backdrop-filter containing block -->
<div use:portal class="fixed inset-0 z-[90] flex justify-center p-4 overflow-y-auto bg-black/60" on:click|self={() => dispatch('close')}>
  <div class="hud-panel !bg-hud-panel w-full max-w-2xl my-auto flex flex-col"
    style="max-height: 85vh; max-height: calc(100dvh - 2rem);">
    <div class="flex items-center justify-between px-4 py-2 border-b border-hud-line">
      <span class="hud-label text-neon-cyan">{$t('nt.allTitle')} // {total}</span>
      <button class="hud-btn ml-auto !px-2" on:click={() => dispatch('close')} title={$t('g.close')}>✕</button>
    </div>

    <div class="px-4 py-2 border-b border-hud-line/60 flex flex-wrap items-center gap-2 text-xs font-mono">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={unread} on:change={() => { page = 1; load() }} />
        <span class="text-hud-dim">{$t('nt.unreadOnly')}</span>
      </label>
      <select class="hud-input !w-auto !py-0.5" bind:value={kind} on:change={() => { page = 1; load() }}>
        <option value="">{$t('nt.allKinds')}</option>
        <option value="reminder">reminder</option>
      </select>
      <div class="ml-auto flex gap-2">
        <button class="hud-btn !py-0.5 !text-[10px]" on:click={clearRead}>{$t('nt.clearRead')}</button>
        <button class="hud-btn !py-0.5 !text-[10px] !text-neon-red border-neon-red/40" on:click={clearAll}>{$t('nt.clearAll')}</button>
      </div>
    </div>

    <div class="overflow-auto flex-1">
      {#each items as n (n.id)}
        <button class="block w-full text-left px-4 py-2 border-b border-hud-line/40 hover:bg-neon-green/5 {n.read_at ? 'opacity-50' : ''}" on:click={() => !n.read_at && markRead(n.id)}>
          <div class="text-xs font-mono {n.read_at ? 'text-hud-dim' : 'text-neon-green'} flex items-center gap-1">
            {#if !n.read_at}<span class="h-1.5 w-1.5 rounded-full bg-neon-green shrink-0"></span>{/if}
            <span class="text-[10px] uppercase text-hud-dim">{n.kind}</span>
            <span class="truncate">{n.title}</span>
          </div>
          <div class="text-[11px] text-hud-dim font-mono mt-0.5 break-words">{n.body}</div>
          <div class="text-[10px] text-hud-dim/70 font-mono mt-0.5">{n.created_at?.slice(0, 19).replace('T', ' ')}</div>
        </button>
      {/each}
      {#if !items.length && !busy}
        <div class="px-4 py-6 text-center hud-label text-hud-dim">{$t('nt.emptyAll')}</div>
      {/if}
    </div>

    <div class="flex items-center justify-center gap-3 py-2 border-t border-hud-line text-xs font-mono">
      <button class="hud-btn !px-3 !py-0.5" disabled={page <= 1} on:click={() => { page--, load() }}>◀</button>
      <span class="text-hud-dim">{$t('ev.page')} {page} / {pages()}</span>
      <button class="hud-btn !px-3 !py-0.5" disabled={page >= pages()} on:click={() => { page++, load() }}>▶</button>
    </div>
  </div>
</div>
