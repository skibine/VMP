<script>
  // region Events [DOMAIN(8): UI,Security; CONCEPT(8): AuditViewer; TECH(6): svelte]
  // Browsable journal of the tamper-evident audit_log: filters (date range / category / VM /
  // status / free text / plane), pagination, row detail expansion, purge (all or older-than-30d).
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  let events = []
  let total = 0
  let page = 1
  const pageSize = 50
  let busy = false
  let vms = []
  let domains = []

  let filters = { from: '', to: '', category: '', scope: '', vm_id: '', domain_id: '', success: '', q: '' }
  let expanded = {} // event id -> true (detail shown in full)

  async function load() {
    busy = true
    try {
      const params = { from: filters.from, to: filters.to, success: filters.success, q: filters.q, page, page_size: pageSize }
      // Direction scoping: vps -> specific VM by id; domains -> specific domain; system -> the
      // VMPulse host's own lifecycle events. The category select stays free unless scoped.
      // Direction chosen but no specific target yet -> 'any' = all events of that direction
      // (the backend matches every event touching some VM / some domain).
      if (filters.scope === 'vm') params.vm_id = filters.vm_id || 'any'
      if (filters.scope === 'domain') params.domain_id = filters.domain_id || 'any' 
      if (filters.scope === 'system') params.category = 'service'
      else if (filters.category) params.category = filters.category
      const res = await api.auditEvents(params)
      events = res.events || []
      total = res.total || 0
    } catch (_) {} finally { busy = false }
  }

  async function loadTargets() {
    // NOTE: the api method is listVms (not listVMs) — the old call was a silent TypeError and
    // left the VM dropdown empty.
    try { vms = (await api.listVms()) || [] } catch (_) { vms = [] }
    try { domains = (await api.listDomains()) || [] } catch (_) { domains = [] }
  }

  function applyFilters() {
    page = 1
    load()
  }

  function onScopeChange() {
    // Cascading: switching the direction resets the specific-target selection.
    filters.vm_id = ''
    filters.domain_id = ''
    if (filters.scope === 'system') filters.category = ''
    applyFilters()
  }

  function resetFilters() {
    filters = { from: '', to: '', category: '', scope: '', vm_id: '', domain_id: '', success: '', q: '' }
    page = 1
    load()
  }

  function totalPages() { return Math.max(1, Math.ceil(total / pageSize)) }

  async function clearAll() {
    if (!confirm($t('ev.confirmClearAll'))) return
    try { await api.clearAudit(); page = 1; await load() } catch (_) {}
  }

  async function clearOld() {
    const d = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10)
    if (!confirm($t('ev.confirmClearOld'))) return
    try { await api.clearAudit(d); if (page > totalPages()) page = 1; await load() } catch (_) {}
  }

  function vmName(id) {
    const v = vms.find((x) => x.id === id)
    return v ? v.name : null
  }
  function domainName(id) {
    const d = domains.find((x) => x.id === id)
    return d ? d.name : null
  }
  // Timestamps are stored UTC; render in the LOCAL system timezone (the machine VMPulse runs on
  // — for the typical single-box install the browser and the server share the clock).
  function localTS(ts) {
    if (!ts) return ''
    const d = new Date(ts)
    if (isNaN(d)) return ts.replace('T', ' ').slice(0, 19)
    const p = (n) => String(n).padStart(2, '0')
    return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
  }

  // Fired alerts are the most important rows: color them by severity (critical=red, warning=amber).
  function alertSeverity(e) {
    if (e.category !== 'alert') return null
    const m = /severity=(\w+)/.exec(e.detail || '')
    return m ? m[1] : 'info'
  }

  function targetOf(e) {
    if (e.vm_id) return vmName(e.vm_id) || 'vm ' + e.vm_id
    if (e.domain_id) return domainName(e.domain_id) || 'domain ' + e.domain_id
    return e.target_type + (e.target_id ? ':' + e.target_id : '')
  }

  const catColor = { auth: 'text-neon-cyan', ai: 'text-neon-green', ssh: 'text-neon-amber', telegram: 'text-sky-300', service: 'text-hud-dim', other: 'text-hud-dim' }

  onMount(() => { loadTargets(); load() })
</script>

<div class="p-4 space-y-3 max-w-6xl mx-auto">
  <div class="flex items-center gap-3">
    <div class="hud-label text-neon-cyan">{$t('ev.title')} // {total}</div>
    <div class="ml-auto flex items-center gap-2">
      <button class="hud-btn" on:click={load} disabled={busy}>{$t('g.refresh')}</button>
      <button class="hud-btn !text-neon-red border-neon-red/40" on:click={clearOld}>{$t('ev.clearOld')}</button>
      <button class="hud-btn !text-neon-red border-neon-red/40" on:click={clearAll}>{$t('ev.clearAll')}</button>
    </div>
  </div>

  <div class="hud-panel p-3 grid grid-cols-2 md:grid-cols-7 gap-2 items-end">
    <label class="space-y-1"><span class="hud-label">{$t('ev.from')}</span>
      <input type="date" class="hud-input" bind:value={filters.from} on:change={applyFilters} /></label>
    <label class="space-y-1"><span class="hud-label">{$t('ev.to')}</span>
      <input type="date" class="hud-input" bind:value={filters.to} on:change={applyFilters} /></label>
    <label class="space-y-1"><span class="hud-label">{$t('ev.category')}</span>
      <select class="hud-input" bind:value={filters.category} on:change={applyFilters}>
        <option value="">—</option>
        {#each ['auth', 'ai', 'ssh', 'telegram', 'service', 'alert', 'config', 'other'] as c}<option value={c}>{c}</option>{/each}
      </select></label>
    <label class="space-y-1"><span class="hud-label">{$t('ev.scope')}</span>
      <select class="hud-input" bind:value={filters.scope} on:change={onScopeChange}>
        <option value="">{$t('ev.scopeAll')}</option>
        <option value="vm">{$t('ev.scopeVM')}</option>
        <option value="domain">{$t('ev.scopeDomain')}</option>
        <option value="system">{$t('ev.scopeSystem')}</option>
      </select></label>
    {#if filters.scope === 'vm'}
      <label class="space-y-1"><span class="hud-label">{$t('ev.scopeVM')}</span>
        <select class="hud-input" bind:value={filters.vm_id} on:change={applyFilters}>
          <option value="">—</option>
          {#each vms as v}<option value={v.id}>{v.name}</option>{/each}
        </select></label>
    {:else if filters.scope === 'domain'}
      <label class="space-y-1"><span class="hud-label">{$t('ev.scopeDomain')}</span>
        <select class="hud-input" bind:value={filters.domain_id} on:change={applyFilters}>
          <option value="">—</option>
          {#each domains as d}<option value={d.id}>{d.name}</option>{/each}
        </select></label>
    {/if}
    <label class="space-y-1"><span class="hud-label">{$t('ev.status')}</span>
      <select class="hud-input" bind:value={filters.success} on:change={applyFilters}>
        <option value="">—</option>
        <option value="true">✓</option>
        <option value="false">✗</option>
      </select></label>
    <div class="flex gap-2">
      <input class="hud-input flex-1" placeholder={$t('ev.search')} bind:value={filters.q}
        on:keydown={(e) => e.key === 'Enter' && applyFilters()} />
      <button class="hud-btn" on:click={resetFilters}>{$t('g.clear')}</button>
    </div>
  </div>

  <div class="hud-panel overflow-x-auto">
    <table class="w-full text-xs font-mono">
      <thead>
        <tr class="text-hud-dim text-left border-b border-hud-line">
          <th class="px-2 py-1.5">{$t('ev.time')}</th>
          <th class="px-2 py-1.5">P</th>
          <th class="px-2 py-1.5">{$t('ev.category')}</th>
          <th class="px-2 py-1.5">{$t('ev.action')}</th>
          <th class="px-2 py-1.5">{$t('ev.target')}</th>
          <th class="px-2 py-1.5">{$t('ev.result')}</th>
          <th class="px-2 py-1.5">user / ip</th>
        </tr>
      </thead>
      <tbody>
        {#each events as e (e.id)}
          <tr class="border-b border-hud-line/40 hover:bg-neon-green/5 cursor-pointer {alertSeverity(e) === 'critical' ? 'bg-neon-red/10' : alertSeverity(e) ? 'bg-neon-amber/10' : ''}" on:click={() => (expanded[e.id] = !expanded[e.id])}>
            <td class="px-2 py-1 whitespace-nowrap text-hud-dim">{localTS(e.ts)}</td>
            <td class="px-2 py-1 {catColor[e.category] || 'text-hud-dim'}">{e.category}</td>
            <td class="px-2 py-1 {alertSeverity(e) === 'critical' ? 'text-neon-red font-bold' : alertSeverity(e) ? 'text-neon-amber font-bold' : 'text-emerald-100'}">{e.action}</td>
            <td class="px-2 py-1 text-neon-cyan truncate max-w-[180px]">{targetOf(e) || '—'}</td>
            <td class="px-2 py-1 {e.success ? 'text-neon-green' : 'text-neon-red'}">{e.success ? '✓' : '✗'}</td>
            <td class="px-2 py-1 text-hud-dim truncate max-w-[160px]">{e.user_id ?? 'system'}{e.ip_address ? ' / ' + e.ip_address : ''}</td>
          </tr>
          {#if expanded[e.id] && e.detail}
            <tr class="border-b border-hud-line/40 bg-neon-green/5"><td colspan="6" class="px-3 py-1.5 text-hud-dim whitespace-pre-wrap break-all">{e.detail}</td></tr>
          {/if}
        {/each}
        {#if !events.length && !busy}
          <tr><td colspan="6" class="px-2 py-4 text-center text-hud-dim">{$t('ev.empty')}</td></tr>
        {/if}
      </tbody>
    </table>
  </div>

  <div class="flex items-center justify-center gap-3 text-xs font-mono">
    <button class="hud-btn !px-3" disabled={page <= 1} on:click={() => (page--, load())}>◀</button>
    <span class="text-hud-dim">{$t('ev.page')} {page} / {totalPages()}</span>
    <button class="hud-btn !px-3" disabled={page >= totalPages()} on:click={() => (page++, load())}>▶</button>
  </div>
</div>
