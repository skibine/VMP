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
  const DIAG_TYPES = ['tcp', 'http', 'tls', 'dns'] // ping is liveness; whois moved to Domains
  const MON_TYPES = ['ping', 'tcp', 'http', 'tls', 'dns']

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
  let pingBusy = false
  let pingMsg = ''
  let nc = { check_type: 'ping', target: '', interval_sec: 60 }
  let checkMsg = ''

  // Live metrics over SSH (snapshot) + interactive terminal (Plane B).
  let snap = { busy: false, data: null, err: '', kind: '' }
  let showTerm = false
  let termKey = 0
  let termNote = { msg: '', kind: '' }

  // Metrics history (pull-poller) + sparklines.
  let metricsRange = '1h'
  let series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [] }
  let metricsBusy = false
  let metricsErr = ''
  let metricsTs = ''
  let metricsTimer = null

  $: vmId != null && loadDetail(vmId)

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
      if (v) {
        edit = { name: v.name, hostname: v.hostname, ip: v.ip, port_ssh: v.port_ssh, tags: (v.tags || []).join(', '), notes: v.notes || '' }
      }
      loadMetrics()
    } catch (e) {
      err = e.message
    } finally {
      if (!soft) loading = false
    }
  }

  $: pingCheck = checks.find((c) => c.check_type === 'ping')
  $: pingResult = pingCheck ? results.find((x) => x.check_id === pingCheck.id) : null
  $: healthWord = !health ? '' : health.status === 'ok' ? 'up' : health.status === 'critical' ? 'down' : health.status === 'warn' ? 'degraded' : 'unknown'
  $: healthColor = healthWord === 'up' ? 'neon-green' : healthWord === 'down' ? 'neon-red' : healthWord === 'degraded' ? 'neon-amber' : 'hud-dim'
  $: healthReason = (() => {
    if (!health || health.status === 'ok') return ''
    const bad = (health.breakdown || []).find((b) => b.status && b.status !== 'ok')
    return bad ? `${bad.check_type} ${bad.status}` : health.status
  })()

  async function pingNow() {
    if (!pingCheck) return
    pingBusy = true
    pingMsg = ''
    try {
      await api.runCheckNow(pingCheck.id)
      await loadDetail(vmId, true)
    } catch (e) {
      pingMsg = e.message
    } finally {
      pingBusy = false
    }
  }

  async function addPing() {
    try {
      await api.createCheck({ vm_id: vmId, target_type: 'vm', check_type: 'ping', interval_sec: 60 })
      await loadDetail(vmId, true)
    } catch (e) {
      pingMsg = e.message
    }
  }

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
      series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [] }
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
        tcp_conns: s.tcp_conns || []
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
        series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [] }
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
      {#if vm.tags?.length}<div class="flex flex-wrap gap-1 mt-2">{#each vm.tags as t}<span class="hud-label border border-hud-line rounded px-1.5 py-0.5">{t}</span>{/each}</div>{/if}
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

    <!-- Row: liveness | diagnostics (compact, two columns) -->
    <div class="grid grid-cols-2 gap-3">
      <section class="hud-panel p-3 space-y-2">
        <div class="hud-label text-neon-cyan">liveness&nbsp;//&nbsp;ping</div>
        {#if pingCheck}
          <div class="flex items-center gap-2 flex-wrap">
            {#if pingResult}
              <span class="hud-label {pingResult.latest_status === 'ok' ? 'text-neon-green' : pingResult.latest_status === 'critical' ? 'text-neon-red' : 'text-neon-amber'} uppercase">{pingResult.latest_status === 'ok' ? 'up' : pingResult.latest_status === 'critical' ? 'down' : 'unknown'}</span>
              {#if pingResult.latest_status === 'ok'}<span class="text-xs text-hud-dim font-mono">{Number(pingResult.latest_latency_ms).toFixed(1)}ms</span>{/if}
              <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={pingNow} disabled={pingBusy}>{pingBusy ? '…' : '▶'}</button>
            {:else}
              <span class="hud-label text-hud-dim">pending…</span>
              <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={pingNow} disabled={pingBusy}>{pingBusy ? '…' : '▶ ping now'}</button>
            {/if}
          </div>
          {#if pingMsg}<div class="text-xs font-mono text-neon-red">{pingMsg}</div>{/if}
        {:else}
          <div class="flex items-center gap-2">
            <span class="hud-label text-hud-dim">no liveness probe</span>
            <button class="hud-btn hud-btn-primary ml-auto" on:click={addPing}>+ add ping</button>
          </div>
        {/if}
      </section>

      <section class="hud-panel p-3 space-y-2">
        <div class="hud-label text-neon-cyan">diagnostics&nbsp;//&nbsp;one-shot</div>
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
