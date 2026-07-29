<script>
  // region DomainDetail [DOMAIN(7): UI; CONCEPT(8]: DomainDetail; TECH(6]: svelte]
  // Per-domain detail shown in the fleet main area when a domain is selected (DNS + cert expiry +
  // whois registration). Auto-probes on domainId change; re-probe + delete inline.
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  export let domainId = null
  export let domainName = ''

  const dispatch = createEventDispatcher()
  let info = null
  let infoBusy = false
  let err = ''

  $: if (domainId != null) probe(domainId)

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
</script>

<div class="h-full overflow-auto p-3 space-y-2">
  <!-- Header: domain name + actions -->
  <div class="hud-panel p-3 space-y-2">
    <div class="flex items-center gap-2">
      <span class="inline-block w-2 h-2 rounded-full shrink-0 bg-neon-amber"></span>
      <h2 class="font-mono text-neon-green text-base truncate">{domainName}</h2>
      <span class="hud-label text-neon-amber uppercase shrink-0 ml-auto">{$t('nav.domains')}</span>
      <button class="hud-btn !py-0.5 !px-2 !text-xs shrink-0" on:click={() => probe(domainId)} disabled={infoBusy}>{infoBusy ? '…' : '↻'}</button>
      <button class="hud-btn !py-0.5 !px-2 !text-xs shrink-0 !text-neon-red border-neon-red/40" on:click={remove} title={$t('g.delete')}>✕</button>
    </div>
  </div>

  <section class="hud-panel p-2.5 space-y-2">
    <div class="flex items-center gap-2">
      <span class="hud-label text-neon-cyan">{$t('dom.info')}</span>
    </div>
    {#if infoBusy}
      <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('dom.probing')}</div>
    {:else if err}
      <div class="text-xs font-mono text-neon-red">{err}</div>
    {:else if info?.error}
      <div class="text-xs font-mono text-neon-red">{info.error}</div>
    {:else if info}
      <!-- Certificate -->
      <div>
        <div class="hud-label text-hud-dim mb-1">{$t('dom.cert')}</div>
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
      </div>
      <!-- DNS records -->
      <div>
        <div class="hud-label text-hud-dim mb-1">{$t('dom.dns')}</div>
        <div class="text-xs font-mono space-y-0.5">
          {#if info.dns?.a?.length}<div><span class="hud-label text-hud-dim">a</span> <span class="text-emerald-200/80">{info.dns.a.join(', ')}</span></div>{/if}
          {#if info.dns?.aaaa?.length}<div><span class="hud-label text-hud-dim">aaaa</span> <span class="text-emerald-200/80">{info.dns.aaaa.join(', ')}</span></div>{/if}
          {#if info.dns?.mx?.length}<div><span class="hud-label text-hud-dim">mx</span> <span class="text-emerald-200/80">{info.dns.mx.join(', ')}</span></div>{/if}
          {#if info.dns?.ns?.length}<div><span class="hud-label text-hud-dim">ns</span> <span class="text-emerald-200/80">{info.dns.ns.join(', ')}</span></div>{/if}
          {#if info.dns?.txt?.length}<div class="min-w-0 break-words"><span class="hud-label text-hud-dim">txt</span> <span class="text-emerald-200/60">{info.dns.txt.slice(0, 3).join(' · ')}</span></div>{/if}
          {#if !info.dns?.a?.length && !info.dns?.ns?.length}<div class="text-hud-dim">{$t('dom.noRecords')}</div>{/if}
        </div>
      </div>
      <!-- Whois -->
      <div>
        <div class="hud-label text-hud-dim mb-1">{$t('dom.whois')}</div>
        <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">registrar</span> {info.whois?.registrar || '—'}</div>
          <div><span class="hud-label text-hud-dim">created</span> {info.whois?.created || '—'}</div>
          <div><span class="hud-label text-hud-dim">expiry</span> {info.whois?.expiry || '—'}</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.status')}</span> {info.whois?.status || '—'}</div>
        </div>
        {#if info.whois?.error}<div class="text-[11px] font-mono text-neon-amber mt-1">{info.whois.error}</div>{/if}
      </div>
    {:else}
      <div class="hud-label text-hud-dim">{$t('dom.empty')}</div>
    {/if}
  </section>
</div>
