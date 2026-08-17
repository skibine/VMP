<script>
  // region DomainDetail [DOMAIN(7): UI; CONCEPT(8]: DomainDetail; TECH(6]: svelte]
  // Per-domain detail shown in the fleet main area when a domain is selected (DNS + cert expiry +
  // whois registration). Auto-probes on domainId change; re-probe + delete inline.
  import { createEventDispatcher } from 'svelte'
  import { get } from 'svelte/store'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  export let domainId = null
  export let domainName = ''

  const dispatch = createEventDispatcher()
  let info = null
  let infoBusy = false
  let err = ''
  let channels = []
  let reminders = [] // all reminders for this domain (list-based; several per kind)
  // per-kind add-row state
  let certAdd = { days: '', chan: 0, repeat: 0 }
  let ownerAdd = { days: '', chan: 0, repeat: 0 }
  let dnsAdd = { chan: 0 }
  let reminderMsg = '', reminderBusy = false
  let dhealth = null // domain fleet health {status, reasons, dns_changed}
  let dnsAck = false

  $: if (domainId != null) { dipinfo = null; dipAt = ''; dports = null; dportAt = ''; probe(domainId); loadReminders(domainId); loadHealth(domainId); loadIntel(domainId) }

  async function loadHealth(id) {
    dnsAck = false
    try { dhealth = await api.domainHealth(id) } catch (_) { dhealth = null }
  }

  async function ackDnsChange() {
    if (dnsAck) return
    dnsAck = true
    try {
      await api.setDnsBaseline(domainId)
      await loadHealth(domainId)
      reminderMsg = $t('dom.dnsAckOk')
    } catch (e) { reminderMsg = e.message; dnsAck = false } finally { dnsAck = false }
  }

  async function loadChannels() {
    try { channels = await api.listChannels() } catch (_) { channels = [] }
  }
  loadChannels()

  async function loadReminders(id) {
    try { reminders = await api.listDomainReminders(id) } catch (_) { reminders = [] }
  }

  $: certRems = reminders.filter((r) => r.kind === 'cert')
  $: dnsRems = reminders.filter((r) => r.kind === 'dns')
  $: ownerRems = reminders.filter((r) => r.kind === 'owner')
  // BUG_FIX_CONTEXT: reactive booleans (not canAdd() in the disabled binding). Svelte 3 does NOT
  // track deps read inside a plain function called in markup, so `disabled={!canAdd('cert')}` never
  // re-evaluated on certAdd.days change -> button stayed disabled / "reminder not added".
  $: certDaysOk = Number(certAdd.days) > 0
  $: ownerDaysOk = Number(ownerAdd.days) > 0
  $: repeatOptions = [
    { v: 0, l: $t('dom.repeatOnce') },
    { v: 3, l: $t('dom.repeat3') },
    { v: 7, l: $t('dom.repeat7') },
    { v: 14, l: $t('dom.repeat14') },
    { v: 30, l: $t('dom.repeat30') },
  ]
  function chanLabel(id) { const o = channelOpts.find((x) => x.id === Number(id)); return o ? o.label : $t('dom.inApp') }

  function addState(kind) { return kind === 'cert' ? certAdd : kind === 'owner' ? ownerAdd : dnsAdd }
  function canAdd(kind) { return kind === 'dns' ? true : Number(addState(kind).days) > 0 }

  async function addReminder(kind) {
    if (!canAdd(kind)) return
    reminderMsg = ''; reminderBusy = true
    const s = addState(kind)
    try {
      await api.createDomainReminder(domainId, {
        kind,
        days: kind === 'dns' ? 0 : Number(s.days) || 0,
        channel_id: Number(s.chan) || 0,
        repeat_days: kind === 'dns' ? 0 : (Number(s.repeat) || 0),
      })
      if (kind === 'cert') certAdd = { days: '', chan: 0, repeat: 0 }
      if (kind === 'owner') ownerAdd = { days: '', chan: 0, repeat: 0 }
      if (kind === 'dns') dnsAdd = { chan: 0 }
      await loadReminders(domainId)
      reminderMsg = $t('dom.reminderSaved')
    } catch (e) { reminderMsg = e.message } finally { reminderBusy = false }
  }

  async function delReminder(id) {
    reminderBusy = true; reminderMsg = ''
    try { await api.deleteDomainReminder(id); await loadReminders(domainId) }
    catch (e) { reminderMsg = e.message } finally { reminderBusy = false }
  }

  $: channelOpts = [{ id: 0, label: $t('dom.inApp') }, ...(channels || []).map((c) => ({ id: c.id, label: c.type + ': ' + c.name }))]

  async function probe(id) {
    info = null
    infoBusy = true
    err = ''
    try {
      info = await api.domainInfo(id)
    } catch (e) {
      err = e.message
    } finally {
      infoBusy = false
    }
  }

  // Domain IP intel (geo/ASN/PTR per resolved A) + port scan of the primary IP — Plane A, keyless.
  // Cached in domain_intel with a fetch timestamp: shown INSTANTLY on domain open (no 30-40s wait),
  // refreshed on demand. The probe endpoints persist their result + stamp on every call.
  let dipinfo = null // [{ip, info:{...}}]
  let dipAt = '' // ISO timestamp of last ip-info fetch
  let dipBusy = false
  let dports = null // {host, ports:[{port,service,open}]}
  let dportAt = '' // ISO timestamp of last port-scan fetch
  let dportBusy = false
  // Load the cached intel instantly on open (empty if never probed). The API returns ipinfo as a
  // parsed array and portscan as a parsed object (NOT strings) — assign directly, do not re-parse.
  async function loadIntel(id) {
    try {
      const c = await api.domainIntel(id)
      if (Array.isArray(c.ipinfo) && c.ipinfo.length) { dipinfo = c.ipinfo; dipAt = c.ipinfo_at || '' }
      if (c.portscan && typeof c.portscan === 'object') { dports = c.portscan; dportAt = c.portscan_at || '' }
    } catch (_) { /* keep empty */ }
  }
  // ago(iso) -> "2 ч назад" / "3 д назад" / "" — humanized cache age.
  // NOTE: do NOT name the local timestamp `t` — it would shadow the imported i18n store `t`,
  // breaking get(t) (subscribe on a Number => crash on any domain that has cached intel).
  function ago(iso) {
    if (!iso) return ''
    const ts = new Date(iso).getTime()
    if (!ts) return ''
    const m = Math.round((Date.now() - ts) / 60000)
    const tr = get(t) // $t can't be used inside a function; read the store value explicitly
    if (m < 1) return tr('dom.justNow')
    if (m < 60) return tr('dom.minAgo', { n: m })
    const h = Math.round(m / 60)
    if (h < 24) return tr('dom.hourAgo', { n: h })
    return tr('dom.dayAgo', { n: Math.round(h / 24) })
  }
  async function loadIPInfo(id) {
    dipBusy = true
    try { const r = await api.domainIPInfo(id); dipinfo = r; dipAt = new Date().toISOString() }
    catch (e) { dipinfo = []; console.error('[DomainDetail] ipinfo failed:', e) } finally { dipBusy = false }
  }
  async function loadPorts(id) {
    dportBusy = true
    try { const r = await api.domainPortScan(id); dports = r; dportAt = new Date().toISOString() }
    catch (e) { dports = { host: '', ports: [] }; console.error('[DomainDetail] portscan failed:', e) } finally { dportBusy = false }
  }

  async function remove() {
    if (!confirm($t('dom.confirmDelete'))) return
    try {
      await api.deleteDomain(domainId)
      dispatch('changed')
    } catch (e) {
      err = e.message
    }
  }

  $: certColor = (s) =>
    s === 'expired' ? 'text-neon-red' : s === 'expiring' ? 'text-neon-amber' : s === 'ok' ? 'text-neon-green' : 'text-hud-dim'
  // Color registration expiry by days remaining, mirroring the cert thresholds (<0 expired, <30 expiring).
  function whoisDaysColor(d) {
    if (d === -1 || d == null) return 'text-hud-dim' // unparseable registrar format
    if (d < 0) return 'text-neon-red'
    if (d < 30) return 'text-neon-amber'
    return 'text-neon-green'
  }
  // Header lamp: same LED status treatment as the fleet (green/warn/critical).
  function domDotClass(st) {
    if (st === 'critical') return 'bg-neon-red text-neon-red led led-pulse'
    if (st === 'warn') return 'bg-neon-amber text-neon-amber led led-pulse'
    return 'bg-neon-green text-neon-green led led-pulse'
  }
</script>

<div class="h-full overflow-auto p-3 space-y-2">
  <!-- Header: domain name + actions -->
  <div class="hud-panel p-3 space-y-2">
    <div class="flex items-center gap-2">
      <span class="inline-block w-2 h-2 rounded-full shrink-0 {domDotClass(dhealth?.status ?? 'ok')}" title={(dhealth?.reasons || []).join('; ')}></span>
      <h2 class="font-mono text-neon-green text-base truncate">{domainName}</h2>
      <div class="ml-auto flex items-center gap-1 shrink-0">
        <button class="hud-btn !py-0.5 !px-2 !text-xs" on:click={() => probe(domainId)} disabled={infoBusy}>{infoBusy ? '…' : $t('g.refresh')}</button>
        <button class="hud-btn !py-0.5 !px-2 !text-xs !text-neon-red border-neon-red/40" on:click={remove}>✕ {$t('g.delete')}</button>
      </div>
    </div>
  </div>

  <div class="space-y-2.5">
    {#if infoBusy}
      <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('dom.probing')}</div>
    {:else if err}
      <div class="text-xs font-mono text-neon-red">{err}</div>
    {:else if info?.error}
      <div class="text-xs font-mono text-neon-red">{info.error}</div>
    {:else if info}
      <div class="text-[10px] text-hud-dim font-mono leading-relaxed">{$t('dom.remindersHint')}</div>
      {#if !channels.length}<div class="text-[10px] text-hud-dim font-mono">{$t('dom.noChannelHint')}</div>{/if}
      <!-- Certificate -->
      <section class="hud-panel p-2.5 space-y-2">
        <div class="hud-label inline-block px-2 py-0.5 rounded text-white" style="background:#E6541C">{$t('dom.cert')}</div>
        {#if info.cert?.present}
          <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs font-mono">
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">issuer</span> {info.cert.issuer || '—'}</div>
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">subject</span> {info.cert.subject || '—'}</div>
            <div><span class="hud-label text-hud-dim">expires</span> <span class={certColor(info.cert.status)}>{info.cert.not_after?.slice(0, 10)} ({info.cert.days_remaining}d)</span></div>
            <div><span class="hud-label text-hud-dim">{$t('vd.status')}</span> <span class={certColor(info.cert.status)}>{info.cert.status}</span></div>
          </div>
        {:else}
          <div class="text-xs font-mono text-hud-dim">{$t('dom.noTls')}</div>
        {/if}
        {#if certRems.length}
          <div class="flex flex-wrap gap-1 mt-1">
            {#each certRems as r (r.id)}
              <span class="text-[10px] font-mono border border-hud-line rounded px-1.5 py-0.5 text-neon-green inline-flex items-center gap-1">{r.days}d · {chanLabel(r.channel_id)}{#if r.repeat_days > 0} · {$t('dom.repeatShort', { n: r.repeat_days })}{/if}<button class="ml-0.5 pl-1 border-l border-hud-line text-neon-red hover:text-neon-green transition-colors" title={$t('g.delete')} on:click|stopPropagation={() => delReminder(r.id)}>✕</button></span>
            {/each}
          </div>
        {/if}
        <div class="text-[10px] hud-label text-hud-dim mt-3 mb-1">{$t('dom.setReminder')}</div>
        <div class="flex items-center gap-1.5 mt-0.5">
          <input class="hud-input !py-0.5 !text-xs w-24 font-mono" type="number" min="1" bind:value={certAdd.days} placeholder={$t('dom.days')} />
          <select class="hud-input !py-0.5 !text-xs w-40" bind:value={certAdd.chan}>{#each channelOpts as o}<option value={o.id}>{o.label}</option>{/each}</select>
          <select class="hud-input !py-0.5 !text-xs w-36" bind:value={certAdd.repeat} title={$t('dom.repeat')}>{#each repeatOptions as o}<option value={o.v}>{o.l}</option>{/each}</select>
          <button class="hud-btn hud-btn-primary !py-0.5 !text-[10px] shrink-0" on:click={() => addReminder('cert')} disabled={reminderBusy || !certDaysOk} title={!certDaysOk ? $t('dom.daysRequired') : ''}>{$t('dom.add')}</button>
        </div>
      </section>
      <!-- DNS records -->
      <section class="hud-panel p-2.5 space-y-2">
        <div class="hud-label inline-block px-2 py-0.5 rounded text-white" style="background:#E6541C">{$t('dom.dns')}</div>
        <div class="text-xs font-mono space-y-0.5">
          {#if info.dns?.a?.length}<div><span class="hud-label text-hud-dim">a</span> <span class="text-emerald-200/80">{info.dns.a.join(', ')}</span></div>{/if}
          {#if info.dns?.aaaa?.length}<div><span class="hud-label text-hud-dim">aaaa</span> <span class="text-emerald-200/80">{info.dns.aaaa.join(', ')}</span></div>{/if}
          {#if info.dns?.mx?.length}<div><span class="hud-label text-hud-dim">mx</span> <span class="text-emerald-200/80">{info.dns.mx.join(', ')}</span></div>{/if}
          {#if info.dns?.ns?.length}<div><span class="hud-label text-hud-dim">ns</span> <span class="text-emerald-200/80">{info.dns.ns.join(', ')}</span></div>{/if}
          {#if info.dns?.txt?.length}<div class="min-w-0 break-words"><span class="hud-label text-hud-dim">txt</span> <span class="text-emerald-200/60">{info.dns.txt.slice(0, 3).join(' · ')}</span></div>{/if}
            {#if !info.dns?.a?.length && !info.dns?.ns?.length}<div class="text-hud-dim">{$t('dom.noRecords')}</div>{/if}
          </div>
        {#if dnsRems.length}
          <div class="flex flex-wrap gap-1 mt-1">
            {#each dnsRems as r (r.id)}
              <span class="text-[10px] font-mono border border-hud-line rounded px-1.5 py-0.5 text-neon-green inline-flex items-center gap-1">{$t('dom.change')} · {chanLabel(r.channel_id)}<button class="ml-0.5 pl-1 border-l border-hud-line text-neon-red hover:text-neon-green transition-colors" title={$t('g.delete')} on:click|stopPropagation={() => delReminder(r.id)}>✕</button></span>
            {/each}
          </div>
        {/if}
        <div class="text-[10px] hud-label text-hud-dim mt-3 mb-1">{$t('dom.enableDns')}</div>
        <div class="flex items-center gap-1.5 mt-0.5">
          <select class="hud-input !py-0.5 !text-xs w-40" bind:value={dnsAdd.chan}>{#each channelOpts as o}<option value={o.id}>{o.label}</option>{/each}</select>
          <button class="hud-btn hud-btn-primary !py-0.5 !text-[10px] shrink-0" on:click={() => addReminder('dns')} disabled={reminderBusy}>{$t('dom.add')}</button>
        </div>
      </section>
      <!-- Whois -->
      <section class="hud-panel p-2.5 space-y-2">
        <div class="hud-label inline-block px-2 py-0.5 rounded text-white" style="background:#E6541C">{$t('dom.whois')}</div>
        <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">registrar</span> {info.whois?.registrar || '—'}</div>
          <div><span class="hud-label text-hud-dim">created</span> {info.whois?.created || '—'}</div>
          <div><span class="hud-label text-hud-dim">expiry</span>{#if info.whois?.expiry}<span class="ml-1 {whoisDaysColor(info.whois.days_remaining)}">{info.whois.expiry}{#if info.whois.days_remaining >= 0}&nbsp;({info.whois.days_remaining}d){/if}</span>{:else}<span class="ml-1">—</span>{/if}</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.status')}</span> {info.whois?.status || '—'}</div>
        </div>
        {#if info.whois?.error}<div class="text-[11px] font-mono text-neon-amber mt-1">{info.whois.error}</div>{/if}
        {#if info.whois?.note}<div class="text-[11px] font-mono text-hud-dim mt-1">{info.whois.note}</div>{/if}
        {#if ownerRems.length}
          <div class="flex flex-wrap gap-1 mt-1">
            {#each ownerRems as r (r.id)}
              <span class="text-[10px] font-mono border border-hud-line rounded px-1.5 py-0.5 text-neon-green inline-flex items-center gap-1">{r.days}d · {chanLabel(r.channel_id)}{#if r.repeat_days > 0} · {$t('dom.repeatShort', { n: r.repeat_days })}{/if}<button class="ml-0.5 pl-1 border-l border-hud-line text-neon-red hover:text-neon-green transition-colors" title={$t('g.delete')} on:click|stopPropagation={() => delReminder(r.id)}>✕</button></span>
            {/each}
          </div>
        {/if}
        <div class="text-[10px] hud-label text-hud-dim mt-3 mb-1">{$t('dom.setReminder')}</div>
        <div class="flex items-center gap-1.5 mt-0.5">
          <input class="hud-input !py-0.5 !text-xs w-24 font-mono" type="number" min="1" bind:value={ownerAdd.days} placeholder={$t('dom.days')} />
          <select class="hud-input !py-0.5 !text-xs w-40" bind:value={ownerAdd.chan}>{#each channelOpts as o}<option value={o.id}>{o.label}</option>{/each}</select>
          <select class="hud-input !py-0.5 !text-xs w-36" bind:value={ownerAdd.repeat} title={$t('dom.repeat')}>{#each repeatOptions as o}<option value={o.v}>{o.l}</option>{/each}</select>
          <button class="hud-btn hud-btn-primary !py-0.5 !text-[10px] shrink-0" on:click={() => addReminder('owner')} disabled={reminderBusy || !ownerDaysOk} title={!ownerDaysOk ? $t('dom.daysRequired') : ''}>{$t('dom.add')}</button>
        </div>
      </section>
      <!-- IP // инфо (geo/ASN/PTR per resolved A) -->
      <section class="hud-panel p-2.5 space-y-2">
        <div class="flex items-center gap-2">
          <span class="hud-label inline-block px-2 py-0.5 rounded text-white" style="background:#E6541C">{$t('dom.ipInfo')}</span>
          {#if dipAt}<span class="text-[10px] text-hud-dim font-mono ml-1">{ago(dipAt)}</span>{/if}
          <div class="ml-auto flex items-center gap-2">
            {#if dipBusy}<span class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('dom.ipinfoBusy')}</span>{/if}
            <button class="hud-btn !py-0.5 !px-2 !text-[10px]" on:click={() => loadIPInfo(domainId)} disabled={dipBusy}>{dipBusy ? '…' : $t('dom.ipInfoGo')}</button>
          </div>
        </div>
        {#if dipinfo}
          {#if dipinfo.length}
            <div class="space-y-1 text-xs font-mono">
              {#each dipinfo as e (e.ip)}
                <div class="border border-hud-line rounded px-2 py-1">
                  <div class="text-emerald-200/90">{e.ip}{#if e.info?.ptr}<span class="text-hud-dim"> · {e.info.ptr}</span>{/if}</div>
                  <div class="text-hud-dim text-[11px]">{#if e.info}{e.info.country || '—'}{e.info.city ? ' · ' + e.info.city : ''}{e.info.country_code ? ' (' + e.info.country_code + ')' : ''}{#if e.info.asn} · AS{e.info.asn}{#if e.info.org} {e.info.org}{/if}{/if}{/if}</div>
                </div>
              {/each}
            </div>
          {:else}
            <div class="text-[11px] text-hud-dim font-mono">{$t('dom.noIp')}</div>
          {/if}
        {/if}
      </section>
      <!-- порт // скан (common ports on the primary resolved IP) -->
      <section class="hud-panel p-2.5 space-y-2">
        <div class="flex items-center gap-2">
          <span class="hud-label inline-block px-2 py-0.5 rounded text-white" style="background:#E6541C">{$t('dom.ports')}</span>
          {#if dportAt}<span class="text-[10px] text-hud-dim font-mono ml-1">{ago(dportAt)}</span>{/if}
          <div class="ml-auto flex items-center gap-2">
            {#if dportBusy}<span class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('dom.portBusy')}</span>{/if}
            <button class="hud-btn !py-0.5 !px-2 !text-[10px]" on:click={() => loadPorts(domainId)} disabled={dportBusy}>{dportBusy ? '…' : $t('dom.portsGo')}</button>
          </div>
        </div>
        {#if dports}
          {@const open = (dports.ports || []).filter((p) => p.open)}
          {#if open.length}
            <div class="flex flex-wrap gap-1">
              {#each open as p (p.port)}<span class="text-[10px] font-mono border border-neon-amber/40 rounded px-1.5 py-0.5 text-neon-amber">{p.port}{#if p.service && p.service !== 'unknown'}<span class="text-hud-dim"> {p.service}</span>{/if}</span>{/each}
            </div>
          {:else}
            <div class="text-[11px] text-hud-dim font-mono">{#if dports.host}{$t('dom.noPorts')}{:else}{$t('dom.noIp')}{/if}</div>
          {/if}
        {/if}
      </section>
    {:else}
      <section class="hud-panel p-2.5"><div class="hud-label text-hud-dim">{$t('dom.empty')}</div></section>
    {/if}
  </div>

  {#if reminderMsg}<div class="px-1 text-[11px] font-mono text-neon-green">{reminderMsg}</div>{/if}
</div>
