<script>
  import { createEventDispatcher, onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import Terminal from './Terminal.svelte'
  import MetricsChart from './MetricsChart.svelte'

  // region VmDetail [DOMAIN(7): UI; CONCEPT(8]: Detail; TECH(6]: svelte]
  // Plain-language detail: health (up/down + reason), ping liveness + run-now, one-shot
  // diagnostics (tcp/http/tls/whois), collapsible monitoring, SSH live metrics + terminal, edit.
  export let vmId = null

  const dispatch = createEventDispatcher()
  const DIAG_TYPES = ['tcp', 'http', 'tls', 'dns', 'dnsbl'] // ping is liveness; whois moved to Domains
  const MON_TYPES = ['ping', 'tcp', 'http', 'tls', 'dns', 'dnsbl']

  let vm = null
  let health = null
  let results = []
  let checks = []
  let loading = true
  let err = ''

  let editMode = false
  let edit = { name: '', hostname: '', ip: '', port_ssh: 22, tags: '', notes: '' }
  let editMsg = ''
  let cred = { ssh_user: '', auth_type: 'password', has_secret: false, secret: '', key_passphrase: '', msg: '', ok: false, busy: false }
  let validate = { kind: '', detail: '' }
  let system = null // inventory from cred-save probe

  let diag = { check_type: 'tcp', param: '', busy: false, msg: '', res: null }
  let nc = { check_type: 'tcp', target: '', interval_sec: 60 }
  let checkMsg = ''

  // Quick-status battery: fixed credential-less probes (ssh/dns/web/tls) auto-run on select.
  let battery = { probes: [], reachable: false, latency_ms: 0, busy: false, err: '' }

  // IP info (GeoIP + ASN + PTR) — Plane A, keyless, auto-loads when the VM has a public IP.
  let ipinfo = { data: null, busy: false, err: '' }

  // Live metrics over SSH (snapshot) + interactive terminal (Plane B).
  let snap = { busy: false, data: null, err: '', kind: '' }
  let showTerm = false
  let termKey = 0
  let termNote = { msg: '', kind: '' }

  // Metrics history (pull-poller) + sparklines.
  let metricsRange = '1h'
  let series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [], net_rx_kbps: [], net_tx_kbps: [] }
  let metricsBusy = false
  let metricsErr = ''
  let metricsTs = ''
  let metricsTimer = null

  $: vmId != null && loadDetail(vmId)
  $: vmId != null && loadBattery(vmId)

  async function loadBattery(id) {
    battery = { probes: [], reachable: false, latency_ms: 0, busy: true, err: '' }
    try {
      const b = await api.battery(id)
      battery = { probes: b.probes || [], reachable: !!b.reachable, latency_ms: b.latency_ms || 0, busy: false, err: '' }
    } catch (e) {
      battery = { probes: [], reachable: false, latency_ms: 0, busy: false, err: e.message }
    }
  }

  async function loadIPInfo(id) {
    ipinfo = { data: null, busy: true, err: '' }
    try {
      const d = await api.ipInfo(id)
      ipinfo = { data: d, busy: false, err: '' }
    } catch (e) {
      ipinfo = { data: null, busy: false, err: e.message }
    }
  }

  // loadDetail(id, soft): soft=true keeps the view mounted (no loading flip) so opened <details>,
  // terminal, etc. are not unmounted+remounted on a refresh (otherwise <details> collapses).
  async function loadDetail(id, soft = false) {
    if (!soft) {
      loading = true
      err = ''
      system = null
      validate = { kind: '', detail: '' }
    }
    try {
      const [v, h, r, c, cr] = await Promise.all([
        api.getVm(id).catch(() => null),
        api.vmHealth(id).catch(() => null),
        api.vmResults(id).catch(() => []),
        api.listChecks(id).catch(() => []),
        api.getVMCreds(id).catch(() => ({ has_secret: false, ssh_user: '', auth_type: 'password' }))
      ])
      vm = v
      health = h
      results = r || []
      checks = c || []
      cred = { ssh_user: cr.ssh_user || '', auth_type: cr.auth_type || 'password', has_secret: !!cr.has_secret, secret: '', msg: '', ok: false, busy: false }
      system = cr.inventory || null
      if (v) {
        edit = { name: v.name, hostname: v.hostname, ip: v.ip, port_ssh: v.port_ssh, tags: (v.tags || []).join(', '), notes: v.notes || '' }
      }
      loadMetrics()
      if (v && v.ip) loadIPInfo(id)
    } catch (e) {
      err = e.message
    } finally {
      if (!soft) loading = false
    }
  }

  $: healthWord = !health ? '' : health.status === 'ok' ? 'up' : health.status === 'critical' ? 'down' : health.status === 'warn' ? 'degraded' : 'unknown'
  $: healthColor = healthWord === 'up' ? 'neon-green' : healthWord === 'down' ? 'neon-red' : healthWord === 'degraded' ? 'neon-amber' : 'hud-dim'
  $: healthReason = (() => {
    if (!health || health.status === 'ok') return ''
    const bad = (health.breakdown || []).find((b) => b.status && b.status !== 'ok')
    return bad ? `${bad.check_type} ${bad.status}` : health.status
  })()

  async function runDiag() {
    diag.busy = true
    diag.msg = ''
    diag.res = null
    const params = {}
    if (diag.check_type === 'tcp' || diag.check_type === 'tls') params.port = Number(diag.param) || 22
    if (diag.check_type === 'http') params.url = diag.param
    try {
      diag.res = await api.diagnose(vmId, { check_type: diag.check_type, params })
    } catch (e) {
      diag.msg = e.message
    } finally {
      diag.busy = false
    }
  }

  async function runNow(c) {
    try {
      await api.runCheckNow(c.id)
      await loadDetail(vmId, true)
    } catch (e) {
      checkMsg = e.message
    }
  }

  function checkKey(c) {
    if (c.check_type === 'tcp' || c.check_type === 'tls') return c.check_type + ':' + (c.params?.port || '')
    if (c.check_type === 'http') return c.check_type + ':' + (c.params?.url || '')
    return c.check_type
  }

  async function addCheck() {
    checkMsg = ''
    const params = {}
    if (nc.check_type === 'tcp' || nc.check_type === 'tls') params.port = Number(nc.target) || 22
    if (nc.check_type === 'http') params.url = nc.target
    const key = checkKey({ check_type: nc.check_type, params })
    if (checks.some((c) => checkKey(c) === key)) {
      checkMsg = 'already exists'
      return
    }
    try {
      await api.createCheck({ vm_id: vmId, target_type: 'vm', check_type: nc.check_type, interval_sec: Number(nc.interval_sec) || 60, params })
      nc.target = ''
      await loadDetail(vmId, true)
    } catch (e) {
      checkMsg = e.message
    }
  }

  async function saveEdit() {
    editMsg = ''
    try {
      await api.updateVm(vmId, {
        name: edit.name, hostname: edit.hostname, ip: edit.ip, port_ssh: Number(edit.port_ssh) || 22,
        tags: edit.tags.split(',').map((t) => t.trim()).filter(Boolean), notes: edit.notes
      })
      editMode = false
      await loadDetail(vmId, true)
      dispatch('changed')
    } catch (e) {
      editMsg = e.message
    }
  }

  async function toggleAIAccess() {
    const next = !vm.ai_enabled
    try {
      await api.setAIAccess(vmId, next)
      vm = { ...vm, ai_enabled: next }
    } catch (e) {
      editMsg = e.message
    }
  }

  async function archiveVm() {
    if (!confirm('Archive this VM? (soft-delete, keeps history)')) return
    await api.archiveVm(vmId).catch(() => {})
    dispatch('changed')
  }

  async function deleteVm() {
    if (!confirm(`Permanently delete "${vm.name}"? This removes the VM and ALL its checks, results, metrics, and credentials. This cannot be undone.`)) return
    try {
      await api.deleteVm(vmId)
      dispatch('deleted')
    } catch (e) {
      editMsg = e.message
    }
  }

  async function saveCred() {
    cred.busy = true; cred.msg = ''; validate = { kind: '', detail: '' }
    try {
      const res = await api.setVMCreds(vmId, { ssh_user: cred.ssh_user, auth_type: cred.auth_type, secret: cred.secret, key_passphrase: cred.key_passphrase })
      cred.secret = ''; cred.key_passphrase = ''
      const fresh = await api.getVMCreds(vmId)
      cred.has_secret = !!fresh.has_secret; cred.ssh_user = fresh.ssh_user; cred.auth_type = fresh.auth_type
      if (res && res.validated) {
        cred.msg = 'saved ✓ connected'; cred.ok = true
        if (res.inventory) system = res.inventory
        await loadMetrics()
      } else if (res && res.error_kind) {
        validate = { kind: res.error_kind, detail: res.error_detail || '' }
        cred.msg = 'saved but not verified'; cred.ok = false
      } else {
        cred.msg = 'saved'; cred.ok = true
      }
    } catch (e) { cred.msg = e.message; cred.ok = false } finally { cred.busy = false }
  }

  async function clearCred() {
    cred.busy = true
    try { await api.deleteVMCreds(vmId); cred.has_secret = false; cred.msg = 'cleared'; cred.ok = true }
    catch (e) { cred.msg = e.message; cred.ok = false } finally { cred.busy = false }
  }

  function classifyErr(m) {
    if (m.includes('no_ssh_credentials')) return 'no_ssh_credentials'
    if (m.includes('host_key_changed')) return 'host_key_changed'
    return 'other'
  }

  async function runSnapshot() {
    snap = { busy: true, data: snap.data, err: '', kind: '' }
    try {
      const d = await api.snapshot(vmId)
      snap = { busy: false, data: d, err: '', kind: '' }
    } catch (e) {
      snap = { busy: false, data: null, err: e.message, kind: classifyErr(e.message) }
    }
  }

  function onTermError(e) {
    const m = e.detail || {}
    if (m.error === 'no_ssh_credentials') termNote = { msg: 'no SSH credentials — set in ⚙ edit', kind: 'no_ssh_credentials' }
    else if (m.error === 'host_key_changed') termNote = { msg: 'host key changed (reinstall/MITM) — reset & reopen', kind: 'host_key_changed' }
    else termNote = { msg: m.detail || m.error || 'connection failed', kind: 'other' }
  }

  async function resetHostKey() {
    try {
      await api.resetHostKey(vmId)
      termNote = { msg: '', kind: '' }
      snap = { busy: false, data: snap.data, err: '', kind: '' }
      termKey++ // remount the terminal to reconnect with fresh TOFU
    } catch (e) {
      termNote = { msg: e.message, kind: 'other' }
    }
  }

  $: memPct = snap.data && snap.data.mem_total_mb ? Math.min(100, (snap.data.mem_used_mb / snap.data.mem_total_mb) * 100) : 0
  $: diskPct = snap.data && snap.data.disk_total_gb ? Math.min(100, (snap.data.disk_used_gb / snap.data.disk_total_gb) * 100) : 0

  async function loadMetrics() {
    if (!vm || !vm.metrics_enabled) {
      series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [], net_rx_kbps: [], net_tx_kbps: [] }
      return
    }
    metricsBusy = true
    metricsErr = ''
    try {
      const d = await api.metrics(vmId, metricsRange)
      const s = d.series || {}
      series = {
        mem_used_mb: s.mem_used_mb || [],
        swap_used_mb: s.swap_used_mb || [],
        disk_used_gb: s.disk_used_gb || [],
        load1: s.load1 || [],
        cpu_pct: s.cpu_pct || [],
        tcp_conns: s.tcp_conns || [],
        net_rx_kbps: s.net_rx_kbps || [],
        net_tx_kbps: s.net_tx_kbps || []
      }
      metricsTs = (d.latest && d.latest.ts) ? d.latest.ts : ''
    } catch (e) {
      metricsErr = e.message
    } finally {
      metricsBusy = false
    }
  }

  async function toggleMetrics() {
    metricsErr = ''
    const next = !vm.metrics_enabled
    try {
      await api.setMetrics(vmId, next)
      vm = { ...vm, metrics_enabled: next }
      if (next) {
        await loadMetrics()
      } else {
        series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [], net_rx_kbps: [], net_tx_kbps: [] }
      }
    } catch (e) {
      metricsErr = e.message
    }
  }

  // auto-refresh sparklines every 30s while metrics are enabled for this VM
  $: if (metricsTimer) { clearInterval(metricsTimer); metricsTimer = null }
  $: if (vm && vm.metrics_enabled) { metricsTimer = setInterval(loadMetrics, 30000) }
  onDestroy(() => { if (metricsTimer) clearInterval(metricsTimer) })

  $: credPH = cred.auth_type === 'key' ? 'paste private key (PEM)' : cred.auth_type === 'agent' ? 'not needed (uses ssh-agent)' : cred.has_secret ? '•••• (new to replace)' : 'password'
  $: needsParam = diag.check_type === 'tcp' || diag.check_type === 'tls' || diag.check_type === 'http'
</script>

<div class="h-full overflow-auto p-4 space-y-4">
  {#if loading}
    <div class="hud-label animate-pulse">loading vm…</div>
  {:else if !vm}
    <div class="hud-panel p-6 text-center">
      {#if err}<div class="hud-label text-neon-red mb-1">load error</div><p class="text-xs text-neon-red font-mono">{err}</p>{:else}<div class="hud-label mb-1">no vm selected</div><p class="text-xs text-hud-dim">Pick a VM from the list.</p>{/if}
    </div>
  {:else}
    <!-- Header: name + health in words -->
    <div class="hud-panel p-4">
      <div class="flex items-center gap-2">
        <h2 class="font-mono text-neon-green text-lg truncate">{vm.name}</h2>
        <span class="hud-label text-{healthColor} ml-auto uppercase">{healthWord}</span>
      </div>
      <div class="text-xs text-hud-dim font-mono mt-1">{vm.ip || vm.hostname}{vm.port_ssh ? ':' + vm.port_ssh : ''}</div>
      {#if healthReason}<div class="text-[11px] font-mono text-{healthColor} mt-0.5">reason: {healthReason}</div>{/if}
      {#if vm.tags?.length}<div class="flex flex-wrap gap-1 mt-2">{#each vm.tags as t}<span class="hud-label border border-hud-line rounded px-1.5 py-0.5">{t}</span>{/each}<span class="hud-label border rounded px-1.5 py-0.5 {vm.ai_enabled ? 'text-neon-cyan border-neon-cyan/40' : 'text-hud-dim border-hud-line'}">ai:{vm.ai_enabled ? 'on' : 'off'}</span></div>{:else}<div class="mt-2"><span class="hud-label border rounded px-1.5 py-0.5 {vm.ai_enabled ? 'text-neon-cyan border-neon-cyan/40' : 'text-hud-dim border-hud-line'}">ai:{vm.ai_enabled ? 'on' : 'off'}</span></div>{/if}
      <div class="flex items-center gap-2 mt-3">
        <button class="hud-btn" on:click={() => (editMode = !editMode)}>{editMode ? '✕ close' : '⚙ edit'}</button>
      </div>
    </div>

    <!-- Edit (fields + creds) — at the top so it's visible above terminal -->
    {#if editMode}
      <section class="hud-panel p-4 space-y-4">
        <div>
          <div class="hud-label text-neon-cyan mb-2">vm fields</div>
          <div class="grid grid-cols-2 gap-3">
            <label class="block space-y-1"><span class="hud-label">name</span><input class="hud-input" bind:value={edit.name} /></label>
            <label class="block space-y-1"><span class="hud-label">hostname</span><input class="hud-input" bind:value={edit.hostname} /></label>
            <label class="block space-y-1"><span class="hud-label">ip</span><input class="hud-input" bind:value={edit.ip} /></label>
            <label class="block space-y-1"><span class="hud-label">ssh port</span><input class="hud-input font-mono" type="number" bind:value={edit.port_ssh} /></label>
            <label class="block space-y-1 col-span-2"><span class="hud-label">tags (comma-separated)</span><input class="hud-input" bind:value={edit.tags} /></label>
            <label class="block space-y-1 col-span-2"><span class="hud-label">notes</span><textarea class="hud-input resize-none" rows="2" bind:value={edit.notes}></textarea></label>
          </div>
          <div class="flex items-center gap-2 mt-3"><button class="hud-btn hud-btn-primary" on:click={saveEdit}>save vm</button><button class="hud-btn" on:click={archiveVm}>archive</button><button class="hud-btn !text-neon-red border-neon-red/40" on:click={deleteVm}>delete</button>{#if editMsg}<span class="text-xs font-mono text-neon-red">{editMsg}</span>{/if}</div>
          <label class="flex items-center gap-2 mt-3 cursor-pointer select-none">
            <input type="checkbox" class="accent-neon-cyan" checked={vm.ai_enabled} on:change={toggleAIAccess} />
            <span class="hud-label">ai access {vm.ai_enabled ? '(granted)' : '(off)'}</span>
            <span class="text-[11px] text-hud-dim">// grant the assistant read access to this VM</span>
          </label>
        </div>
        <div class="border-t border-hud-line pt-3">
          <div class="flex items-center gap-2 mb-2"><span class="hud-label text-neon-cyan">ssh credentials</span>{#if cred.has_secret}<span class="hud-label text-neon-green border border-neon-green/30 rounded px-1.5">set</span>{:else}<span class="hud-label text-hud-dim border border-hud-line rounded px-1.5">none</span>{/if}</div>
          <div class="grid grid-cols-3 gap-2">
            <input class="hud-input" placeholder="ssh user" bind:value={cred.ssh_user} />
            <select class="hud-input" bind:value={cred.auth_type}><option value="password">password</option><option value="key">key</option><option value="agent">agent</option></select>
            {#if cred.auth_type === 'key'}
              <textarea class="hud-input font-mono resize-none" rows="2" placeholder={credPH} bind:value={cred.secret}></textarea>
            {:else}
              <input class="hud-input" type="password" placeholder={credPH} bind:value={cred.secret} />
            {/if}
          </div>
          {#if cred.auth_type === 'key'}
            <input class="hud-input mt-2" type="password" placeholder="key passphrase (leave empty if none)" bind:value={cred.key_passphrase} />
          {/if}
          <div class="flex items-center gap-2 mt-2"><button class="hud-btn hud-btn-primary" on:click={saveCred} disabled={cred.busy}>{cred.busy ? 'saving…' : 'save & probe'}</button><button class="hud-btn" on:click={clearCred} disabled={cred.busy || !cred.has_secret}>clear</button>{#if cred.msg}<span class="text-xs font-mono {cred.ok ? 'text-neon-green' : 'text-neon-amber'}">{cred.msg}</span>{/if}</div>
          {#if validate.kind}
            <div class="text-xs font-mono text-neon-red mt-2">
              connection check: <span class="uppercase">{validate.kind}</span> {#if validate.kind === 'no_credentials'}— enter a secret above{:else if validate.kind === 'auth_failed'}— wrong user/password/key{:else if validate.kind === 'host_key_changed'}— <button class="hud-btn !px-2 !py-0.5" on:click={resetHostKey}>reset host key</button>{/if}
              {#if validate.detail}<div class="text-hud-dim mt-1 break-all">{validate.detail}</div>{/if}
            </div>
          {/if}
        </div>
      </section>
    {/if}

    <!-- Status battery (auto-run on select) + one-shot tools -->
    <div class="grid grid-cols-2 gap-3">
      <section class="hud-panel p-3 space-y-2">
        <div class="flex items-center gap-2">
          <span class="hud-label text-neon-cyan">status&nbsp;//&nbsp;battery</span>
          {#if !battery.busy && battery.probes.length}
            <span class="hud-label ml-auto uppercase {battery.reachable ? 'text-neon-green' : 'text-neon-red'}">{battery.reachable ? 'reachable' : 'no ssh'}</span>
          {/if}
          <button class="hud-btn !py-0.5" on:click={() => loadBattery(vmId)} disabled={battery.busy}>{battery.busy ? '…' : '↻'}</button>
        </div>
        {#if battery.busy}
          <div class="hud-label text-hud-dim animate-pulse">probing ssh · dns · web · tls…</div>
        {:else if battery.err}
          <div class="text-xs font-mono text-neon-red">{battery.err}</div>
        {:else}
          <div class="flex flex-wrap gap-1.5">
            {#each battery.probes as p}
              <div class="flex items-center gap-1 border border-hud-line rounded px-1.5 py-0.5 text-xs font-mono">
                <span class="{p.status === 'ok' ? 'text-neon-green' : 'text-hud-dim'}">{p.status === 'ok' ? '✓' : '✗'}</span>
                <span class="text-hud-dim">{p.name}</span>
                {#if p.status === 'ok'}<span class="text-hud-dim">{Number(p.latency_ms).toFixed(0)}ms</span>{/if}
              </div>
            {/each}
          </div>
          {#if !battery.probes.length}<div class="hud-label text-hud-dim">no probes</div>{/if}
        {/if}
      </section>

      <section class="hud-panel p-3 space-y-2">
        <div class="hud-label text-neon-cyan">tools&nbsp;//&nbsp;probe</div>
        <div class="grid grid-cols-[auto_1fr_auto] gap-2 items-center">
          <select class="hud-input" bind:value={diag.check_type}>
            {#each DIAG_TYPES as t}<option value={t}>{t}</option>{/each}
          </select>
          <input class="hud-input" placeholder={needsParam ? (diag.check_type === 'http' ? 'http://host/path' : 'port') : '—'} bind:value={diag.param} disabled={!needsParam} />
          <button class="hud-btn hud-btn-primary" on:click={runDiag} disabled={diag.busy}>{diag.busy ? '…' : 'run'}</button>
        </div>
        {#if diag.msg}<div class="text-xs font-mono text-neon-red">{diag.msg}</div>{/if}
        {#if diag.res}
          <div class="border border-hud-line rounded px-2 py-1 text-xs font-mono flex items-center gap-2">
            <span class="hud-label {diag.res.status === 'ok' ? 'text-neon-green' : diag.res.status === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{diag.res.status}</span>
            <span class="text-hud-dim">{Number(diag.res.latency_ms || 0).toFixed(1)}ms</span>
            <span class="text-emerald-200/70 truncate">{diag.res.message}</span>
          </div>
        {/if}
      </section>
    </div>

    <!-- IP info (GeoIP + ASN + PTR) — Plane A, keyless -->
    {#if vm.ip}
      <section class="hud-panel p-3 space-y-2">
        <div class="flex items-center gap-2">
          <span class="hud-label text-neon-cyan">ip&nbsp;//&nbsp;info</span>
          <span class="text-xs text-hud-dim font-mono truncate ml-1">{vm.ip}</span>
          <button class="hud-btn !py-0.5 ml-auto" on:click={() => loadIPInfo(vmId)} disabled={ipinfo.busy}>{ipinfo.busy ? '…' : '↻'}</button>
        </div>
        {#if ipinfo.busy}
          <div class="hud-label text-hud-dim animate-pulse">resolving geo · asn · ptr…</div>
        {:else if ipinfo.err}
          <div class="text-xs font-mono text-neon-red">{ipinfo.err}</div>
        {:else if ipinfo.data}
          <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs font-mono">
            <div class="truncate"><span class="hud-label text-hud-dim">location</span> {ipinfo.data.country || '—'}{ipinfo.data.city ? ' · ' + ipinfo.data.city : ''}{ipinfo.data.country_code ? ' (' + ipinfo.data.country_code + ')' : ''}</div>
            <div class="truncate"><span class="hud-label text-hud-dim">asn</span> {ipinfo.data.asn || '—'}</div>
            <div class="truncate"><span class="hud-label text-hud-dim">isp</span> {ipinfo.data.isp || ipinfo.data.org || '—'}</div>
            <div class="truncate"><span class="hud-label text-hud-dim">tz</span> {ipinfo.data.timezone || '—'}</div>
            <div class="col-span-2 md:col-span-4 truncate"><span class="hud-label text-hud-dim">ptr</span> {ipinfo.data.ptr || '—'}</div>
          </div>
          {#if ipinfo.data.geo_error}<div class="text-[11px] font-mono text-neon-amber">geo: {ipinfo.data.geo_error}</div>{/if}
        {/if}
      </section>
    {/if}

    <!-- System profile (inventory from cred-save probe) -->
    {#if system}
      <section class="hud-panel p-3 space-y-2">
        <div class="hud-label text-neon-cyan">system&nbsp;//&nbsp;profile</div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="truncate"><span class="hud-label text-hud-dim">os</span> {system.os || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">kernel</span> {system.kernel || '—'} {system.arch}</div>
          <div class="truncate col-span-2"><span class="hud-label text-hud-dim">cpu</span> {system.cpu_model || '—'}</div>
          <div><span class="hud-label text-hud-dim">ram</span> {system.mem_total_mb} MB</div>
          <div><span class="hud-label text-hud-dim">swap</span> {system.swap_total_mb} MB</div>
          <div><span class="hud-label text-hud-dim">packages</span> {system.packages || '—'}</div>
          <div><span class="hud-label text-hud-dim">services</span> {system.services || '—'}</div>
          <div class="col-span-2"><span class="hud-label text-hud-dim">up</span> {system.uptime || '—'}</div>
        </div>
        {#if system.ports?.length}
          <div class="text-xs font-mono"><span class="hud-label text-hud-dim">listening ports:</span> <span class="text-emerald-200">{system.ports.join(', ')}</span></div>
        {/if}
        {#if system.docker?.length}
          <div class="text-xs font-mono space-y-0.5"><span class="hud-label text-hud-dim">docker:</span>{#each system.docker as d}<div class="text-emerald-200/80 pl-2 truncate">▸ {d.replace(/\|/g, ' · ')}</div>{/each}</div>
        {/if}
        {#if system.services_list?.length}
          <details class="text-xs font-mono">
            <summary class="hud-label text-hud-dim cursor-pointer">running services ({system.services_list.length})</summary>
            <div class="flex flex-wrap gap-1 mt-1">{#each system.services_list as svc}<span class="text-emerald-200/70 border border-hud-line rounded px-1">{svc}</span>{/each}</div>
          </details>
        {/if}
      </section>
    {/if}

    <!-- Metrics history (pull-poller) — charts stacked 2x2 -->
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">metrics&nbsp;//&nbsp;history</span>
        <span class="hud-label text-hud-dim ml-auto">polls via ssh</span>
        <button class="hud-btn !py-0.5" on:click={toggleMetrics}>{vm.metrics_enabled ? '● on' : '○ off'}</button>
      </div>
      {#if vm.metrics_enabled}
        <div class="flex items-center gap-2 flex-wrap">
          {#each ['1h', '24h', '7d'] as r}
            <button class="hud-btn !py-0.5 {metricsRange === r ? 'hud-btn-primary' : ''}" on:click={() => { metricsRange = r; loadMetrics() }}>{r}</button>
          {/each}
          <button class="hud-btn !py-0.5" on:click={loadMetrics} disabled={metricsBusy}>{metricsBusy ? '…' : '↻'}</button>
          {#if metricsTs}<span class="text-[10px] font-mono text-hud-dim ml-auto">last: {metricsTs.slice(11, 19)}</span>{/if}
        </div>
        {#if metricsErr}<div class="text-xs font-mono text-neon-red">{metricsErr}</div>{/if}
        <div class="grid grid-cols-2 gap-2">
          <MetricsChart label="cpu" unit="%" data={series.cpu_pct} decimals={0} color="#f97316" />
          <MetricsChart label="mem used" unit="MB" data={series.mem_used_mb} color="#22d3ee" />
          <MetricsChart label="swap used" unit="MB" data={series.swap_used_mb} color="#a78bfa" />
          <MetricsChart label="disk used" unit="GB" data={series.disk_used_gb} decimals={1} color="#22c55e" />
          <MetricsChart label="load 1m" data={series.load1} decimals={2} color="#eab308" />
          <MetricsChart label="tcp conns" data={series.tcp_conns} color="#38bdf8" />
          <MetricsChart label="net rx" unit="KB/s" data={series.net_rx_kbps} decimals={1} color="#34d399" />
          <MetricsChart label="net tx" unit="KB/s" data={series.net_tx_kbps} decimals={1} color="#f472b6" />
        </div>
      {:else}
        <p class="text-xs text-hud-dim">// enable to collect CPU/RAM/disk/load history over SSH (no agent install). Needs SSH creds.</p>
      {/if}
    </section>

    <!-- Live (interactive terminal) + one-shot snapshot (only when metrics history is off) -->
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">live&nbsp;//&nbsp;terminal</span>
        {#if !vm.metrics_enabled}
          <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={runSnapshot} disabled={snap.busy}>{snap.busy ? '…' : '▶ snapshot'}</button>
        {/if}
        <button class="hud-btn !py-0.5 {!vm.metrics_enabled ? '' : 'ml-auto'}" on:click={() => { showTerm = !showTerm; termNote = { msg: '', kind: '' } }}>{showTerm ? '✕ close' : '> terminal'}</button>
      </div>

      {#if !vm.metrics_enabled}
        {#if snap.err}
          <div class="text-xs font-mono text-neon-red">
            {snap.err}
            {#if snap.kind === 'no_ssh_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{/if}
            {#if snap.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>reset host key</button>{/if}
          </div>
        {/if}
        {#if snap.data}
          <div class="space-y-1.5">
            <div>
              <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>memory</span><span>{snap.data.mem_used_mb}/{snap.data.mem_total_mb} MB</span></div>
              <div class="h-1.5 bg-hud-line rounded"><div class="h-full bg-neon-cyan rounded" style="width:{memPct}%"></div></div>
            </div>
            <div>
              <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>disk /</span><span>{Number(snap.data.disk_used_gb).toFixed(1)}/{Number(snap.data.disk_total_gb).toFixed(1)} GB</span></div>
              <div class="h-1.5 bg-hud-line rounded"><div class="h-full {diskPct > 85 ? 'bg-neon-red' : 'bg-neon-green'} rounded" style="width:{diskPct}%"></div></div>
            </div>
            <div class="grid grid-cols-3 gap-2 text-xs font-mono">
              <div><span class="hud-label text-hud-dim">load</span> <span class="text-neon-green">{snap.data.load1?.toFixed(2)}</span> <span class="text-hud-dim">{snap.data.load5?.toFixed(2)}/{snap.data.load15?.toFixed(2)}</span></div>
              <div><span class="hud-label text-hud-dim">cpus</span> <span>{snap.data.cpu_count}</span></div>
              <div class="truncate"><span class="hud-label text-hud-dim">up</span> <span class="text-hud-dim">{snap.data.uptime}</span></div>
            </div>
          </div>
        {:else if !snap.err}
          <p class="text-xs text-hud-dim">// run a snapshot to fetch CPU / RAM / disk / load over SSH now.</p>
        {/if}
      {:else}
        <p class="text-xs text-hud-dim">// live CPU/RAM/disk/load values are in the metrics history above; enable a terminal session here.</p>
      {/if}

      {#if showTerm}
        <div class="space-y-2">
          {#key termKey}
            <Terminal vmId={vmId} on:error={onTermError} />
          {/key}
          {#if termNote.msg}
            <div class="text-xs font-mono text-neon-red">
              {termNote.msg}
              {#if termNote.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>reset host key</button>{/if}
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <!-- Monitoring (collapsible) -->
    <details class="hud-panel p-3">
      <summary class="hud-label text-neon-cyan cursor-pointer">monitoring&nbsp;//&nbsp;{checks.length} scheduled</summary>
      <div class="space-y-2 mt-2">
        {#if !checks.length}<div class="hud-label">none</div>{:else}
          <div class="space-y-1">
            {#each checks as c (c.id)}
              {@const r = results.find((x) => x.check_id === c.id)}
              <div class="flex items-center gap-2 text-xs font-mono border border-hud-line rounded px-2 py-1">
                <span class="text-emerald-200 w-14">{c.check_type}</span>
                {#if r}<span class="hud-label {r.latest_status === 'ok' ? 'text-neon-green' : r.latest_status === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{r.latest_status}</span><span class="text-hud-dim">{Number(r.latest_latency_ms).toFixed(1)}ms</span>{:else}<span class="hud-label text-hud-dim">pending</span>{/if}
                <span class="ml-auto text-hud-dim">/{c.interval_sec}s</span>
                <button class="hud-btn !px-2 !py-0.5" on:click={() => runNow(c)}>▶</button>
              </div>
            {/each}
          </div>
        {/if}
        <div class="grid grid-cols-[auto_1fr_auto_auto] gap-2 pt-1 items-center">
          <select class="hud-input" bind:value={nc.check_type}>{#each MON_TYPES as t}<option value={t}>{t}</option>{/each}</select>
          <input class="hud-input" placeholder={nc.check_type === 'http' ? 'url' : (nc.check_type === 'tcp' || nc.check_type === 'tls') ? 'port' : '—'} bind:value={nc.target} />
          <input class="hud-input w-20" type="number" placeholder="sec" bind:value={nc.interval_sec} />
          <button class="hud-btn hud-btn-primary" on:click={addCheck}>+ add</button>
        </div>
        {#if checkMsg}<div class="text-xs font-mono text-neon-red">{checkMsg}</div>{/if}
      </div>
    </details>
  {/if}
</div>
