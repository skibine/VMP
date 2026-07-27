<script>
  // region Domains [DOMAIN(7): UI; CONCEPT(8]: Domains; TECH(6]: svelte]
  // Domains view: list monitored domains, add new, and probe each (DNS + cert expiry + whois age).
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  let domains = []
  let name = ''
  let err = ''
  let busy = false
  // selected domain id -> info probe result
  let selected = null
  let info = null
  let infoBusy = false

  $: load()

  async function load() {
    try {
      domains = await api.listDomains()
    } catch (e) {
      err = e.message
    }
  }

  async function add() {
    err = ''
    name = name.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!name) return
    busy = true
    try {
      await api.createDomain({ name })
      name = ''
      await load()
    } catch (e) {
      err = e.message
    } finally {
      busy = false
    }
  }

  async function remove(id) {
    if (!confirm($t('dom.confirmDelete'))) return
    try {
      await api.deleteDomain(id)
      if (selected === id) { selected = null; info = null }
      await load()
    } catch (e) {
      err = e.message
    }
  }

  async function probe(d) {
    selected = d.id
    info = null
    infoBusy = true
    try {
      info = await api.domainInfo(d.id)
    } catch (e) {
      info = { error: e.message }
    } finally {
      infoBusy = false
    }
  }

  $: certColor = (s) => s === 'expired' ? 'text-neon-red' : s === 'expiring' ? 'text-neon-amber' : s === 'ok' ? 'text-neon-green' : 'text-hud-dim'
</script>

<div class="h-full overflow-auto p-4 space-y-4 max-w-5xl mx-auto">
  <div class="hud-panel p-4 space-y-3">
    <div class="flex items-center gap-2">
      <h2 class="font-mono text-neon-green text-lg">{$t('dom.title', { n: domains.length })}</h2>
    </div>
    <form on:submit|preventDefault={add} class="flex items-center gap-2">
      <input class="hud-input flex-1" placeholder="example.com" bind:value={name} />
      <button class="hud-btn hud-btn-primary" disabled={busy}>{busy ? '…' : $t('dom.add')}</button>
    </form>
    {#if err}<div class="text-xs font-mono text-neon-red">{err}</div>{/if}
    {#if !domains.length}
      <div class="hud-label text-hud-dim">{$t('dom.empty')}</div>
    {:else}
      <div class="space-y-1">
        {#each domains as d (d.id)}
          <div class="flex items-center gap-2 border border-hud-line rounded px-2 py-1.5">
            <button class="font-mono text-emerald-200 text-sm flex-1 text-left truncate {selected === d.id ? 'text-neon-cyan' : ''}" on:click={() => probe(d)}>{d.name}</button>
            <button class="hud-btn !py-0.5" on:click={() => probe(d)} disabled={infoBusy && selected === d.id}>{infoBusy && selected === d.id ? '…' : $t('dom.probe')}</button>
            <button class="hud-btn !py-0.5 !text-neon-red border-neon-red/40" on:click={() => remove(d.id)}>✕</button>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  {#if selected}
    <section class="hud-panel p-4 space-y-3">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">{$t('dom.info')}</span>
        <span class="font-mono text-emerald-200 ml-1">{domains.find((d) => d.id === selected)?.name}</span>
      </div>
      {#if infoBusy}
        <div class="hud-label text-hud-dim animate-pulse">{$t('dom.probing')}</div>
      {:else if info?.error}
        <div class="text-xs font-mono text-neon-red">{info.error}</div>
      {:else if info}
        <!-- Certificate -->
        <div>
          <div class="hud-label text-hud-dim mb-1">{$t('dom.cert')}</div>
          {#if info.cert?.present}
            <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs font-mono">
              <div class="truncate"><span class="hud-label text-hud-dim">issuer</span> {info.cert.issuer || '—'}</div>
              <div class="truncate"><span class="hud-label text-hud-dim">subject</span> {info.cert.subject || '—'}</div>
              <div><span class="hud-label text-hud-dim">expires</span> <span class={certColor(info.cert.status)}>{info.cert.not_after?.slice(0, 10)} ({info.cert.days_remaining}d)</span></div>
              <div><span class="hud-label text-hud-dim">{$t('vd.status')}</span> <span class={certColor(info.cert.status)}>{info.cert.status}</span></div>
            </div>
          {:else}
            <div class="text-xs font-mono text-hud-dim">{$t('dom.noTls')}</div>
          {/if}
        </div>
        <!-- DNS records -->
        <div>
          <div class="hud-label text-hud-dim mb-1">{$t('dom.dns')}</div>
          <div class="text-xs font-mono space-y-0.5">
            {#if info.dns?.a?.length}<div><span class="hud-label text-hud-dim">a</span> <span class="text-emerald-200/80">{info.dns.a.join(', ')}</span></div>{/if}
            {#if info.dns?.aaaa?.length}<div><span class="hud-label text-hud-dim">aaaa</span> <span class="text-emerald-200/80">{info.dns.aaaa.join(', ')}</span></div>{/if}
            {#if info.dns?.mx?.length}<div><span class="hud-label text-hud-dim">mx</span> <span class="text-emerald-200/80">{info.dns.mx.join(', ')}</span></div>{/if}
            {#if info.dns?.ns?.length}<div><span class="hud-label text-hud-dim">ns</span> <span class="text-emerald-200/80">{info.dns.ns.join(', ')}</span></div>{/if}
            {#if info.dns?.txt?.length}<div class="truncate"><span class="hud-label text-hud-dim">txt</span> <span class="text-emerald-200/60">{info.dns.txt.slice(0, 3).join(' · ')}</span></div>{/if}
            {#if !info.dns?.a?.length && !info.dns?.ns?.length}<div class="text-hud-dim">{$t('dom.noRecords')}</div>{/if}
          </div>
        </div>
        <!-- Whois -->
        <div>
          <div class="hud-label text-hud-dim mb-1">{$t('dom.whois')}</div>
          <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs font-mono">
            <div class="truncate"><span class="hud-label text-hud-dim">registrar</span> {info.whois?.registrar || '—'}</div>
            <div><span class="hud-label text-hud-dim">created</span> {info.whois?.created || '—'}</div>
            <div><span class="hud-label text-hud-dim">expiry</span> {info.whois?.expiry || '—'}</div>
            <div><span class="hud-label text-hud-dim">{$t('vd.status')}</span> {info.whois?.status || '—'}</div>
          </div>
          {#if info.whois?.error}<div class="text-[11px] font-mono text-neon-amber mt-1">{info.whois.error}</div>{/if}
        </div>
      {/if}
    </section>
  {/if}
</div>
