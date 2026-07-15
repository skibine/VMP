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
  let nc = { check_type: 'ping', target: '', interval_sec: 60 }
  let checkMsg = ''

  // Quick-status battery: fixed credential-less probes (ssh/dns/web/tls) auto-run on select.
  let battery = { probes: [], reachable: false, latency_ms: 0, busy: false, err: '' }

  // External port scan (common ports) — Plane A, no creds. Auto-runs on select.
  let portscan = { ports: [], busy: false, err: '' }

  // IP info (GeoIP + ASN + PTR) — Plane A, keyless, auto-loads when the VM has a public IP.
  let ipinfo = { data: null, busy: false, err: '' }

  // Packages list is lazy-loaded (the full list can be hundreds of names; not worth shipping on
  // every detail open) — fetched only when the "packages" details block is expanded.
  let packagesList = null

  // Manual refresh of the SSH inventory profile.
  let profileBusy = false

  // Recent log errors (journalctl) — Plane B one-shot over SSH.
  let errors = { data: null, busy: false, err: '', kind: '', range: '24h' }

  // Available package updates (apt simulate) — Plane B one-shot over SSH.
  let updates = { data: null, busy: false, err: '', kind: '' }

  // Web-server virtual hosts (nginx/apache config) — Plane B one-shot over SSH.
  let vhosts = { data: null, busy: false, err: '', kind: '' }

  // Site info (HTTP headers + security + CMS) — Plane A, keyless, for the VM's site (or any URL).
  let siteinfo = { data: null, busy: false, err: '', url: '' }

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
  $: vmId != null && loadPortScan(vmId)
  // Whether the battery found a web server on :80 (gates the site-info panel).
  $: batteryWebOk = battery.probes.some((p) => p.name === 'web' && p.status === 'ok')
  // User-configured alert checks (system liveness is auto-managed + hidden from this list).
  $: userChecks = checks.filter((c) => !c.system)
  // Liveness verdict: the box is UP if anything answered (ping/ssh/web/tls) OR any port is open.
  // A single port (e.g. ssh:22) failing must NOT flip a reachable box to "down".
  $: portscanOpen = portscan.ports.filter((p) => p.open).length
  $: livenessUp = battery.reachable || portscanOpen > 0
  $: livenessEvidence = (() => {
    const ping = battery.probes.find((p) => p.name === 'ping' && p.status === 'ok')
    if (ping) return 'ping ' + Number(ping.latency_ms).toFixed(0) + 'ms'
    if (batteryWebOk) return 'web :80'
    if (battery.probes.some((p) => p.name === 'ssh' && p.status === 'ok')) return 'ssh'
    if (portscanOpen > 0) return portscanOpen + ' ports open'
    return 'unreachable'
  })()

  async function loadBattery(id) {
    battery = { probes: [], reachable: false, latency_ms: 0, busy: true, err: '' }
    try {
      const b = await api.battery(id)
      if (id !== vmId) return // user switched VM while in flight — drop the stale response
      battery = { probes: b.probes || [], reachable: !!b.reachable, latency_ms: b.latency_ms || 0, busy: false, err: '' }
    } catch (e) {
      if (id !== vmId) return
      battery = { probes: [], reachable: false, latency_ms: 0, busy: false, err: e.message }
    }
  }

  async function loadPortScan(id) {
    portscan = { ports: [], busy: true, err: '' }
    try {
      const d = await api.portScan(id)
      if (id !== vmId) return
      portscan = { ports: d.ports || [], busy: false, err: '' }
    } catch (e) {
      if (id !== vmId) return
      portscan = { ports: [], busy: false, err: e.message }
    }
  }

  // probeHint explains a battery probe in a tooltip (the UI otherwise doesn't say what each is).
  function probeHint(name) {
    switch (name) {
      case 'ping': return 'ICMP echo — does the box respond to ping? (true liveness)'
      case 'ssh': return 'TCP reach to the SSH port — is SSH reachable on this port?'
      case 'dns': return 'resolves the hostname to an IP (only if a domain name is set)'
      case 'web': return 'HTTP probe to :80 — is a web server answering?'
      case 'tls': return 'TLS handshake to :443 — is HTTPS present?'
      default: return name
    }
  }

  async function loadIPInfo(id) {
    ipinfo = { data: null, busy: true, err: '' }
    try {
      const d = await api.ipInfo(id)
      if (id !== vmId) return // stale: a different VM is now selected
      ipinfo = { data: d, busy: false, err: '' }
    } catch (e) {
      if (id !== vmId) return
      ipinfo = { data: null, busy: false, err: e.message }
    }
  }

  async function loadErrors() {
    errors = { data: null, busy: true, err: '', kind: '', range: errors.range }
    try {
      const d = await api.vmErrors(vmId, errors.range)
      if (d.error) {
        errors = { data: null, busy: false, err: d.detail || d.error, kind: d.error, range: errors.range }
      } else {
        errors = { data: d, busy: false, err: '', kind: '', range: errors.range }
      }
    } catch (e) {
      errors = { data: null, busy: false, err: e.message, kind: '', range: errors.range }
    }
  }

  async function loadUpdates() {
    updates = { data: null, busy: true, err: '', kind: '' }
    try {
      const d = await api.vmUpdates(vmId)
      if (d.error) {
        updates = { data: null, busy: false, err: d.detail || d.error, kind: d.error }
      } else {
        updates = { data: d, busy: false, err: '', kind: '' }
      }
    } catch (e) {
      updates = { data: null, busy: false, err: e.message, kind: '' }
    }
  }

  async function loadVHosts() {
    vhosts = { data: null, busy: true, err: '', kind: '' }
    try {
      const d = await api.vmVHosts(vmId)
      if (d.error) {
        vhosts = { data: null, busy: false, err: d.detail || d.error, kind: d.error }
      } else {
        vhosts = { data: d, busy: false, err: '', kind: '' }
      }
    } catch (e) {
      vhosts = { data: null, busy: false, err: e.message, kind: '' }
    }
  }

  async function loadSiteInfo() {
    siteinfo = { data: null, busy: true, err: '', url: siteinfo.url }
    try {
      const d = await api.siteInfo(vmId, siteinfo.url)
      siteinfo = { data: d, busy: false, err: d.fetch_error || '', url: siteinfo.url }
    } catch (e) {
      siteinfo = { data: null, busy: false, err: e.message, url: siteinfo.url }
    }
  }

  async function loadPackages() {
    if (packagesList) return // already loaded for this VM
    try {
      const d = await api.vmInventory(vmId)
      packagesList = d.packages_list || []
    } catch (e) {
      packagesList = []
    }
  }

  async function refreshProfile() {
    profileBusy = true
    try {
      const d = await api.refreshInventory(vmId)
      if (d.error) {
        editMsg = d.detail || d.error
      } else if (d.inventory) {
        system = d.inventory
        packagesList = null // force lazy reload on next expand
      }
    } catch (e) {
      editMsg = e.message
    } finally {
      profileBusy = false
    }
  }

  // loadDetail(id, soft): soft=true keeps the view mounted (no loading flip) so opened <details>,
  // terminal, etc. are not unmounted+remounted on a refresh (otherwise <details> collapses).
  async function loadDetail(id, soft = false) {
    if (!soft) {
      loading = true
      err = ''
      system = null
      packagesList = null
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
      if (v) siteinfo = { data: null, busy: false, err: '', url: 'http://' + (v.ip || v.hostname) + '/' }
    } catch (e) {
      err = e.message
    } finally {
      if (!soft) loading = false
    }
  }

  $: healthWord = !health ? '' : health.status === 'ok' ? 'up' : health.status === 'critical' ? 'down' : health.status === 'warn' ? 'degraded' : 'unknown'
  $: healthColor = healthWord === 'up' ? 'neon-green' : healthWord === 'down' ? 'neon-red' : healthWord === 'degraded' ? 'neon-amber' : 'hud-dim'
  // Header verdict = LIVENESS (is the box up?), not the K2 service-health score. A reachable box
  // stays "up" even if a monitored service (e.g. ssh:22) is critical.
  $: headerVerdict = battery.busy ? '…' : (livenessUp ? 'up' : (battery.probes.length ? 'down' : '…'))
  $: headerColor = headerVerdict === 'up' ? 'neon-green' : headerVerdict === 'down' ? 'neon-red' : 'hud-dim'
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

  async function removeCheck(c) {
    if (!confirm('Delete this ' + c.check_type + ' check?')) return
    try {
      await api.deleteCheck(c.id)
      await loadDetail(vmId, true)
      dispatch('changed')
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
    if (m.includes('no_credentials')) return 'no_credentials'
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
    if (m.error === 'no_credentials') termNote = { msg: 'no SSH credentials — set in ⚙ edit', kind: 'no_credentials' }
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
        <span class="hud-label text-{headerColor} ml-auto uppercase">{headerVerdict}</span>
      </div>
      <div class="text-xs text-hud-dim font-mono mt-1">{vm.ip || vm.hostname}{vm.port_ssh ? ':' + vm.port_ssh : ''}</div>
      {#if !livenessUp && !battery.busy && battery.probes.length}<div class="text-[11px] font-mono text-neon-red mt-0.5">unreachable — no ping, no open ports</div>{/if}
      {#if livenessUp && healthReason}<div class="text-[11px] font-mono text-neon-amber mt-0.5">service: {healthReason} (box is up)</div>{/if}
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

    <!-- Responsive grid: as many 200px columns as fit (container-responsive), battery+terminal full width. -->
    <div class="grid grid-cols-[repeat(auto-fill,minmax(190px,1fr))] gap-3">

    <!-- Status battery (auto-run on select) + one-shot tools -->
    <div class="grid grid-cols-2 gap-3 col-span-full">
      <section class="hud-panel p-3 space-y-2">
        <div class="flex items-center gap-2">
          <span class="hud-label text-neon-cyan">status&nbsp;//&nbsp;battery</span>
          {#if !battery.busy && battery.probes.length}
            <span class="hud-label ml-auto uppercase {livenessUp ? 'text-neon-green' : 'text-neon-red'}">{livenessUp ? 'up' : 'down'} · <span class="normal-case">{livenessEvidence}</span></span>
          {/if}
          <button class="hud-btn !py-0.5" on:click={() => loadBattery(vmId)} disabled={battery.busy}>{battery.busy ? '…' : '↻'}</button>
        </div>
        {#if battery.busy}
          <div class="hud-label text-hud-dim animate-pulse">probing ping · ssh · dns · web · tls…</div>
        {:else if battery.err}
          <div class="text-xs font-mono text-neon-red">{battery.err}</div>
        {:else}
          <div class="flex flex-wrap gap-1.5">
            {#each battery.probes as p}
              <div class="flex items-center gap-1 border border-hud-line rounded px-1.5 py-0.5 text-xs font-mono" title={probeHint(p.name)}>
                <span class="{p.status === 'ok' ? 'text-neon-green' : 'text-hud-dim'}">{p.status === 'ok' ? '✓' : '✗'}</span>
                <span class="text-hud-dim">{p.name === 'ssh' ? 'ssh:' + (vm.port_ssh || 22) : p.name}</span>
                {#if p.status === 'ok'}<span class="text-hud-dim">{Number(p.latency_ms).toFixed(0)}ms</span>{/if}
              </div>
            {/each}
          </div>
          <div class="text-[11px] text-hud-dim">// ping=ICMP echo · ssh=:22 reachable (set the real port in ⚙ edit if non-standard) · web=:80 · tls=:443 · dns=name→ip</div>
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

    <!-- Ports // exposed (external scan, Plane A, no creds) -->
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">ports&nbsp;//&nbsp;exposed</span>
        <span class="text-xs text-hud-dim font-mono ml-1">{portscan.ports.filter((p) => p.open).length} open / {portscan.ports.length} scanned</span>
        <button class="hud-btn !py-0.5 ml-auto" on:click={() => loadPortScan(vmId)} disabled={portscan.busy}>{portscan.busy ? '…' : '↻'}</button>
      </div>
      {#if portscan.busy}
        <div class="hud-label text-hud-dim animate-pulse">scanning common ports…</div>
      {:else if portscan.err}
        <div class="text-xs font-mono text-neon-red">{portscan.err}</div>
      {:else}
        {#if portscanOpen > 0}
          <div class="flex flex-wrap gap-1.5">
            {#each portscan.ports.filter((p) => p.open) as p}
              <div class="flex items-center gap-1 border border-neon-green/40 bg-neon-green/5 rounded px-1.5 py-0.5 text-xs font-mono" title={'open — ' + p.service}>
                <span class="text-neon-green">●</span>
                <span class="text-emerald-100">{p.port}</span>
                <span class="text-hud-dim">{p.service}</span>
              </div>
            {/each}
          </div>
        {/if}
        <details class="text-[11px] font-mono text-hud-dim">
          <summary class="cursor-pointer">{portscan.ports.length - portscanOpen} closed/filtered of {portscan.ports.length} common ports</summary>
          <div class="flex flex-wrap gap-1 mt-1 opacity-60">
            {#each portscan.ports.filter((p) => !p.open) as p}<span class="border border-hud-line rounded px-1">○ {p.port}</span>{/each}
          </div>
        </details>
        <div class="text-[11px] text-hud-dim">// scanned from the VM Pulse host (external view). only open ports shown above.</div>
      {/if}
    </section>

    <!-- System profile (inventory from cred-save probe) -->
    {#if system}
      <section class="hud-panel p-3 space-y-2 col-span-full">
        <div class="flex items-center gap-2">
          <div class="hud-label text-neon-cyan">system&nbsp;//&nbsp;profile</div>
          <button class="hud-btn !py-0.5 ml-auto" on:click={refreshProfile} disabled={profileBusy}>{profileBusy ? '…' : '↻ refresh'}</button>
        </div>
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
        {#if system.packages != null}
          <details class="text-xs font-mono" on:open={loadPackages}>
            <summary class="hud-label text-hud-dim cursor-pointer">packages ({system.packages})</summary>
            {#if packagesList === null}
              <div class="hud-label text-hud-dim mt-1 animate-pulse">loading…</div>
            {:else if packagesList.length}
              <div class="flex flex-wrap gap-1 mt-1 max-h-32 overflow-auto">{#each packagesList as p}<span class="text-emerald-200/60 border border-hud-line rounded px-1">{p}</span>{/each}</div>
            {:else}
              <div class="hud-label text-hud-dim mt-1">no package list</div>
            {/if}
          </details>
        {/if}
      </section>
    {/if}

    <!-- Logs // errors (journalctl priority=err, Plane B over SSH) -->
    <section class="hud-panel p-3 space-y-2 col-span-full">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">logs&nbsp;//&nbsp;errors</span>
        {#each ['1h', '24h', '7d'] as r}
          <button class="hud-btn !py-0.5 {errors.range === r ? 'hud-btn-primary' : ''}" on:click={() => { errors.range = r }}>{r}</button>
        {/each}
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadErrors} disabled={errors.busy}>{errors.busy ? '…' : '▶ scan'}</button>
      </div>
      {#if errors.err}
        <div class="text-xs font-mono text-neon-red">{errors.err}{#if errors.kind === 'no_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{:else if errors.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>reset host key</button>{/if}</div>
      {:else if errors.data}
        <div class="text-xs font-mono text-hud-dim">{errors.data.count} error(s) in last {errors.data.window}</div>
        {#if errors.data.entries?.length}
          <div class="space-y-1 max-h-56 overflow-auto">
            {#each errors.data.entries as e}
              <div class="text-xs font-mono border-l-2 border-neon-red/40 pl-2">
                <span class="text-hud-dim">{e.ts.slice(11)}</span> <span class="text-neon-amber">{e.unit}</span> <span class="text-emerald-200/70 break-all">{e.msg}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="hud-label text-neon-green">no errors ✓</div>
        {/if}
      {/if}
    </section>

    <!-- Updates // available (apt simulate, Plane B over SSH) -->
    {#if cred.has_secret}
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">updates&nbsp;//&nbsp;available</span>
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadUpdates} disabled={updates.busy}>{updates.busy ? '…' : '▶ check'}</button>
      </div>
      {#if updates.err}
        <div class="text-xs font-mono text-neon-red">{updates.err}{#if updates.kind === 'no_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{/if}</div>
      {:else if updates.data}
        <div class="flex items-center gap-3 flex-wrap">
          {#if updates.data.count === 0}
            <span class="hud-label text-neon-green">system up to date ✓</span>
          {:else}
            <span class="text-xs font-mono {updates.data.security_count > 0 ? 'text-neon-red' : 'text-neon-amber'}">{updates.data.count} upgradable{#if updates.data.security_count > 0} · {updates.data.security_count} security{/if}</span>
          {/if}
          {#if updates.data.reboot_required}
            <span class="hud-label text-neon-red border border-neon-red/40 rounded px-1.5">⚠ reboot required</span>
          {/if}
          <span class="hud-label text-hud-dim">mgr: {updates.data.manager}</span>
        </div>
        {#if updates.data.packages?.length}
          <details class="text-xs font-mono">
            <summary class="hud-label text-hud-dim cursor-pointer">packages ({updates.data.packages.length})</summary>
            <div class="flex flex-wrap gap-1 mt-1 max-h-40 overflow-auto">{#each updates.data.packages as p}<span class="border rounded px-1 {p.security ? 'text-neon-red border-neon-red/40' : 'text-emerald-200/70 border-hud-line'}" title={p.version + ' · ' + p.suite}>{p.name}{#if p.security} ⚡{/if}</span>{/each}</div>
          </details>
        {/if}
      {/if}
    </section>
    {/if}

    <!-- Sites // vhosts (nginx/apache config, Plane B over SSH) — only when SSH creds exist -->
    {#if cred.has_secret}
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">sites&nbsp;//&nbsp;vhosts</span>
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadVHosts} disabled={vhosts.busy}>{vhosts.busy ? '…' : '▶ scan'}</button>
      </div>
      {#if vhosts.err}
        <div class="text-xs font-mono text-neon-red">{vhosts.err}{#if vhosts.kind === 'no_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{/if}</div>
      {:else if vhosts.data}
        <div class="text-xs font-mono text-hud-dim">server: {vhosts.data.server}{#if vhosts.data.listening?.length}<span class="ml-2">listening: {vhosts.data.listening.join(', ')}</span>{/if}{#if !vhosts.data.root}<span class="ml-2 text-neon-amber">(non-root)</span>{/if}</div>
        {#if vhosts.data.sites?.length}
          <div class="flex flex-wrap gap-1">{#each vhosts.data.sites as s}<span class="text-emerald-200/80 border border-hud-line rounded px-1.5 py-0.5 text-xs font-mono">{s.name}{#if s.port}<span class="text-hud-dim">:{s.port}</span>{/if}</span>{/each}</div>
        {:else if vhosts.data.server === 'unknown'}
          <div class="hud-label text-neon-amber">web ports open (:80/:443) but SSH user is non-root — can't read the server config. Use a root/sudo login to inspect vhosts.</div>
        {:else if vhosts.data.server !== 'none'}
          <div class="hud-label text-neon-amber">{vhosts.data.server} serves :80/:443 but no readable vhost config (container / non-standard path)</div>
        {:else}
          <div class="hud-label text-hud-dim">no web server on :80/:443</div>
        {/if}
      {/if}
    </section>
    {/if}

    <!-- Site info (HTTP headers + security + CMS, Plane A keyless) — only when a web port answers -->
    {#if vm.ip && (battery.busy || batteryWebOk)}
    <section class="hud-panel p-3 space-y-2">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">site&nbsp;//&nbsp;info</span>
        <input class="hud-input text-xs flex-1 min-w-0" bind:value={siteinfo.url} placeholder="http://host/" />
        <button class="hud-btn hud-btn-primary !py-0.5" on:click={loadSiteInfo} disabled={siteinfo.busy}>{siteinfo.busy ? '…' : '▶ scan'}</button>
      </div>
      {#if siteinfo.err}
        <div class="text-xs font-mono text-neon-red">{siteinfo.err}</div>
      {:else if siteinfo.data}
        <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="truncate"><span class="hud-label text-hud-dim">status</span> {siteinfo.data.status || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">server</span> {siteinfo.data.server || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">powered</span> {siteinfo.data.powered_by || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">cms</span> <span class="text-neon-cyan">{siteinfo.data.cms || '—'}{#if siteinfo.data.cms_version}<span class="text-hud-dim"> {siteinfo.data.cms_version}</span>{/if}</span></div>
        </div>
        <div class="text-xs font-mono">
          <span class="hud-label text-hud-dim">security:</span>
          {#each Object.entries(siteinfo.data.security_headers || {}) as [k, v]}
            <span class="ml-1 {v ? 'text-neon-green' : 'text-neon-red'}">{v ? '✓' : '✗'}{k.replace('X-Frame-Options','XFO').replace('Strict-Transport-Security','HSTS').replace('Content-Security-Policy','CSP').replace('X-Content-Type-Options','XCTO').replace('Referrer-Policy','RP')}</span>
          {/each}
          <span class="ml-2 hud-label {siteinfo.data.security_score >= 60 ? 'text-neon-green' : siteinfo.data.security_score >= 30 ? 'text-neon-amber' : 'text-neon-red'}">{siteinfo.data.security_score}/100</span>
        </div>
        {#if siteinfo.data.redirected}<div class="text-[11px] font-mono text-hud-dim">→ {siteinfo.data.final_url}</div>{/if}
      {/if}
    </section>
    {/if}

    <!-- Metrics history (pull-poller) — charts stacked 2x2 -->
    <section class="hud-panel p-3 space-y-2 col-span-full">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">metrics&nbsp;//&nbsp;history</span>
        <span class="hud-label text-hud-dim ml-auto">ssh pull · ~15min</span>
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
        <p class="text-xs text-hud-dim">// enable to collect CPU/RAM/disk/load history over SSH (no agent install). Needs SSH creds. Tip: use a restricted monitoring user (sudo allowlist) instead of root — same metrics, smaller blast radius. On-demand snapshot below works without enabling this.</p>
      {/if}
    </section>

    <!-- Live (interactive terminal) + one-shot snapshot (only when metrics history is off) -->
    <section class="hud-panel p-3 space-y-2 col-span-full">
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
            {#if snap.kind === 'no_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{/if}
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

    <!-- Alert checks (user-configured; system liveness is auto-managed and hidden) -->
    <details class="hud-panel p-3">
      <summary class="hud-label text-neon-cyan cursor-pointer">alert checks&nbsp;//&nbsp;{userChecks.length}</summary>
      <div class="text-[11px] text-hud-dim mt-1">// extra checks for alerting on specific services. Liveness (the status dot) is always-on automatically — you don't configure it here.</div>
      <div class="space-y-2 mt-2">
        {#if !userChecks.length}<div class="hud-label text-hud-dim">// none — liveness is tracked automatically. Add a check (e.g. tcp:443) to alert on a specific service.</div>{:else}
          <div class="space-y-1">
            {#each userChecks as c (c.id)}
              {@const r = results.find((x) => x.check_id === c.id)}
              <div class="flex items-center gap-2 text-xs font-mono border border-hud-line rounded px-2 py-1">
                <span class="text-emerald-200 w-14">{c.check_type}</span>
                {#if r}<span class="hud-label {r.latest_status === 'ok' ? 'text-neon-green' : r.latest_status === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{r.latest_status}</span><span class="text-hud-dim">{Number(r.latest_latency_ms).toFixed(1)}ms</span>{:else}<span class="hud-label text-hud-dim">pending</span>{/if}
                <span class="ml-auto text-hud-dim">/{c.interval_sec}s</span>
                <button class="hud-btn !px-2 !py-0.5" on:click={() => runNow(c)} title="run now">▶</button>
                <button class="hud-btn !px-2 !py-0.5 !text-neon-red border-neon-red/40" on:click={() => removeCheck(c)} title="delete">✕</button>
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

    </div><!-- /dense panel grid -->
  {/if}
</div>
