<script>
  import { createEventDispatcher, onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { bumpAlerts, gotoSettings, bumpCreds } from '../lib/stores.js'
  import { coverage, vmAlerted, refreshAlertCoverage } from '../lib/alerts.js'
  import Bell from './Bell.svelte'
  import Lock from './Lock.svelte'
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
  let cred = { ssh_user: '', auth_type: 'password', has_secret: false, has_sudo: false, secret: '', key_passphrase: '', sudo_password: '', msg: '', ok: false, busy: false }
  let validate = { kind: '', detail: '' }
  let system = null // inventory from cred-save probe
  let twofaOn = true // 2FA enabled? loaded per-select; SSH credentials cannot be saved without it

  let diag = { check_type: 'tcp', param: '', busy: false, msg: '', res: null }
  let nc = { check_type: 'ping', target: '', interval_sec: 60 }
  let checkMsg = ''

  // Quick-status battery: fixed credential-less probes (ssh/dns/web/tls) auto-run on select.
  let battery = { probes: [], reachable: false, latency_ms: 0, busy: false, err: '' }

  // External port scan (common ports) — Plane A, no creds. Auto-runs on select.
  let portscan = { ports: [], busy: false, err: '' }
  // Deep (wide-range) TCP scan: finds non-standard open ports the fixed common-port scan misses.
  // On-demand (button) + modal with a ban/duration warning — NOT auto-run (slow, noisy to IDS).
  let deepscan = { open: [], busy: false, err: '', scope: 'fast', show: false, scanned: 0 }
  let exposures = { findings: [], busy: false, err: '' }

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

  // Switching VMs must tear down any open terminal: the Terminal's WebSocket URL is bound to the
  // PREVIOUS vmId at mount time, so without this the old SSH session leaks server-side (each switch
  // spawns a new one — that's what blew past the per-user session limit) and stale output shows on
  // the new VM. Closing showTerm unmounts Terminal -> onDestroy -> ws.close().
  let prevVmId = null
  $: if (vmId != null && vmId !== prevVmId) {
    prevVmId = vmId
    showTerm = false
    termKey++
    // Reset the manually-triggered / one-shot per-VM states so the previous VM's results don't
    // leak into the newly-selected one (deep-scan ports, exposures findings, diag result, errors,
    // updates — none of these auto-reload on vmId change, so they'd persist until a re-run).
    deepscan = { open: [], busy: false, err: '', scope: 'fast', show: false, scanned: 0 }
    exposures = { findings: [], busy: false, err: '' }
    diag = { check_type: 'tcp', param: '', busy: false, msg: '', res: null }
    errors = { data: null, busy: false, err: '', kind: '', range: '24h' }
    updates = { data: null, busy: false, err: '', kind: '' }
  }

  // Metrics history (pull-poller) + sparklines.
  let metricsRange = '1h'
  let series = { mem_used_mb: [], swap_used_mb: [], disk_used_gb: [], load1: [], cpu_pct: [], tcp_conns: [], net_rx_kbps: [], net_tx_kbps: [] }
  let metricsBusy = false
  let metricsErr = ''
  let metricsTs = ''
  let metricsTimer = null

  $: vmId != null && loadDetail(vmId)
  $: vmId != null && loadBattery(vmId)
  $: vmId != null && refreshAlertCoverage() // ensure the shared bell coverage is fresh for this VM
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

  // Per-server alert routing uses the SHARED coverage store. The bell is ON when the server is
  // covered by a rule AND has >=1 delivery channel attached (in-app / telegram / webhook — all
  // optional, chosen in the picker). in-app is just another selectable channel.
  let bellOpen = false
  let vmAlertBusy = false
  let vmAlertMsg = ''
  let pickerSel = new Set() // working selection of channels in the open picker
  $: bellOn = vmId != null && vmAlerted(vmId, $coverage)
  $: bellTitle = bellOn ? $t('vd.alertOnHint') : $t('vd.alertHint')
  function openBell() {
    if (vmAlertBusy) return
    pickerSel = new Set($coverage.vmChannels.get(vmId) || [])
    bellOpen = true
  }
  // Save the picker: apply the chosen channels (in-app / telegram / webhook — all optional). With
  // channels selected -> ensure coverage (scoped rule if no fleet) + unmute. With none selected ->
  // remove coverage (delete scoped rule, or mute under the fleet rule): bell off, no delivery.
  async function savePicker() {
    vmAlertBusy = true; vmAlertMsg = ''
    const ids = [...pickerSel]
    try {
      await api.setVMAlertChannels(vmId, ids)
      if (ids.length > 0) {
        if (!$coverage.fleetOn && !$coverage.scopedIds.has(vmId)) {
          await api.createAlertRule({
            name: (vm.name || 'server') + ' down', check_type: 'liveness', trigger_status: 'critical',
            severity: 'critical', cooldown_sec: 300, vm_id: vmId, enabled: true,
          })
        }
        if ($coverage.mutedIds.has(vmId)) { await api.setAlertMute(vmId, false) }
      } else {
        await removeCoverage()
      }
      bellOpen = false
      await refreshAlertCoverage()
      bumpAlerts()
    } catch (e) { vmAlertMsg = e.message } finally { vmAlertBusy = false }
  }
  // removeCoverage: delete this VM's scoped rule, or mute it under the fleet rule.
  async function removeCoverage() {
    if ($coverage.scopedIds.has(vmId)) {
      const rules = await api.listAlertRules()
      const scoped = (rules || []).find((r) => r.vm_id === vmId && r.check_type === 'liveness')
      if (scoped) await api.deleteAlertRule(scoped.id)
    } else if ($coverage.fleetOn) {
      await api.setAlertMute(vmId, true)
    }
  }
  // Turn this server's alert OFF (explicit button): clear channels + remove coverage.
  async function turnOffAlert() {
    vmAlertBusy = true; vmAlertMsg = ''
    try {
      await api.setVMAlertChannels(vmId, [])
      await removeCoverage()
      bellOpen = false
      await refreshAlertCoverage()
      bumpAlerts()
    } catch (e) { vmAlertMsg = e.message } finally { vmAlertBusy = false }
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

  async function runDeepScan() {
    const scope = deepscan.scope
    const id = vmId // capture at start: the scan outlives a possible VM switch
    deepscan = { ...deepscan, open: [], busy: true, err: '', show: false }
    try {
      const d = await api.deepScan(id, scope)
      if (id !== vmId) return // switched away mid-scan -> discard, don't leak onto the new VM
      deepscan = { open: d.open || [], busy: false, err: '', scope, show: false, scanned: scope === 'full' ? 65535 : 0 }
    } catch (e) {
      if (id !== vmId) return
      deepscan = { ...deepscan, open: [], busy: false, err: e.message, show: false }
    }
  }

  async function loadExposures(id) {
    exposures = { findings: [], busy: true, err: '' }
    try {
      const d = await api.exposures(id)
      if (id !== vmId) return
      exposures = { findings: d.findings || [], busy: false, err: '' }
      // The endpoint persists the verdict into the exposures system check; refetch health so the
      // header verdict + card reflect the fresh scan immediately (not the 6h periodic cadence).
      api.vmHealth(id).then((h) => { if (id === vmId) health = h }).catch(() => {})
    } catch (e) {
      if (id !== vmId) return
      exposures = { findings: [], busy: false, err: e.message }
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
    const id = vmId // capture: a VM switch mid-request must not land the result on the new VM
    errors = { data: null, busy: true, err: '', kind: '', range: errors.range }
    try {
      const d = await api.vmErrors(id, errors.range)
      if (id !== vmId) return
      if (d.error) {
        errors = { data: null, busy: false, err: d.detail || d.error, kind: d.error, range: errors.range }
      } else {
        errors = { data: d, busy: false, err: '', kind: '', range: errors.range }
      }
    } catch (e) {
      if (id !== vmId) return
      errors = { data: null, busy: false, err: e.message, kind: '', range: errors.range }
    }
  }

  async function loadUpdates() {
    const id = vmId // capture: a switch mid-request must not leak onto the new VM
    updates = { data: null, busy: true, err: '', kind: '' }
    try {
      const d = await api.vmUpdates(id)
      if (id !== vmId) return
      if (d.error) {
        updates = { data: null, busy: false, err: d.detail || d.error, kind: d.error }
      } else {
        updates = { data: d, busy: false, err: '', kind: '' }
      }
    } catch (e) {
      if (id !== vmId) return
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
      const [v, h, r, c, cr, fa] = await Promise.all([
        api.getVm(id).catch(() => null),
        api.vmHealth(id).catch(() => null),
        api.vmResults(id).catch(() => []),
        api.listChecks(id).catch(() => []),
        api.getVMCreds(id).catch(() => ({ has_secret: false, ssh_user: '', auth_type: 'password' })),
        api.twoFAStatus().catch(() => ({ enabled: true }))
      ])
      vm = v
      health = h
      results = r || []
      checks = c || []
      twofaOn = !!fa.enabled
      // Pre-fill the exposures panel with the LAST stored scan (from the periodic exposures check),
      // so it isn't empty on VM open — the "scan" button re-runs fresh. The findings live in the
      // check result's latest_detail.findings.
      const expStored = (r || []).find((x) => x.check_type === 'exposures' && x.latest_detail?.findings)
      if (expStored) exposures = { findings: expStored.latest_detail.findings, busy: false, err: '' }
      cred = { ssh_user: cr.ssh_user || '', auth_type: cr.auth_type || 'password', has_secret: !!cr.has_secret, has_sudo: !!cr.has_sudo, secret: '', sudo_password: '', msg: '', ok: false, busy: false }
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
  $: lampClass = headerVerdict === 'up' ? 'bg-neon-green text-neon-green led led-pulse' : headerVerdict === 'down' ? 'bg-neon-red text-neon-red led led-pulse' : 'bg-hud-dim'
  $: healthReason = (() => {
    if (!health || health.status === 'ok') return ''
    const rank = { critical: 3, warn: 2, unknown: 1 }
    const bad = (health.breakdown || [])
      .filter((b) => b.status && b.status !== 'ok')
      .sort((a, b) => (rank[b.status] || 0) - (rank[a.status] || 0))[0]
    if (!bad) return health.status
    // Actionable: the check's own message (e.g. ".git repository exposed"), not "exposures warn".
    return bad.message || `${bad.check_type} ${bad.status}`
  })()

  async function runDiag() {
    const id = vmId // capture: a switch mid-probe must not leak the result onto the new VM
    diag.busy = true
    diag.msg = ''
    diag.res = null
    const params = {}
    if (diag.check_type === 'tcp' || diag.check_type === 'tls') params.port = Number(diag.param) || 22
    if (diag.check_type === 'http') params.url = diag.param
    try {
      const res = await api.diagnose(id, { check_type: diag.check_type, params })
      if (id !== vmId) return
      diag.res = res
    } catch (e) {
      if (id !== vmId) return
      diag.msg = e.message
    } finally {
      if (id === vmId) diag.busy = false
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
      const res = await api.setVMCreds(vmId, { ssh_user: cred.ssh_user, auth_type: cred.auth_type, secret: cred.secret, key_passphrase: cred.key_passphrase, sudo_password: cred.sudo_password })
      cred.secret = ''; cred.key_passphrase = ''; cred.sudo_password = ''
      const fresh = await api.getVMCreds(vmId)
      cred.has_secret = !!fresh.has_secret; cred.has_sudo = !!fresh.has_sudo; cred.ssh_user = fresh.ssh_user; cred.auth_type = fresh.auth_type
      bumpCreds() // refresh lock badges in sidebar/fleet
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
    try { await api.deleteVMCreds(vmId); cred.has_secret = false; cred.msg = 'cleared'; cred.ok = true; bumpCreds() }
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

<div class="h-full overflow-auto p-3 space-y-2">
  {#if loading}
    <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('g.loading')}</div>
  {:else if !vm}
    <div class="hud-panel p-6 text-center">
      {#if err}<div class="hud-label text-neon-red mb-1">load error</div><p class="text-xs text-neon-red font-mono">{err}</p>{:else}<div class="hud-label mb-1">no vm selected</div><p class="text-xs text-hud-dim">{$t('list.empty')}</p>{/if}
    </div>
  {:else}
    <!-- Header: dense single-block — status lamp + name + address + verdict + badges -->
    <div class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
        <span class="inline-block w-2 h-2 rounded-full shrink-0 {lampClass}" title={headerVerdict}></span>
        <h2 class="font-mono text-neon-green text-base truncate">
          {#if vm.kind && vm.kind !== 'server'}<span class="text-[10px] font-mono px-1 py-0.5 mr-1 rounded border border-neon-amber/40 text-neon-amber uppercase align-middle">{$t('vmk.equipment')}</span>{/if}
          {vm.name}
        </h2>
        <span class="text-xs text-hud-dim font-mono shrink-0">{vm.ip || vm.hostname}{vm.port_ssh && vm.port_ssh !== 22 ? ':' + vm.port_ssh : ''}</span>
        <span class="hud-label text-{headerColor} uppercase shrink-0 ml-auto">{headerVerdict === 'up' ? $t('vd.up') : headerVerdict === 'down' ? $t('vd.down') : headerVerdict}</span>
        <button class="hud-btn !py-0.5 !px-2 !text-xs shrink-0" on:click={() => (editMode = !editMode)} title={$t('vd.edit')}>{editMode ? $t('g.close') : $t('vd.edit')}</button>
      </div>
      {#if !livenessUp && !battery.busy && battery.probes.length}
        <div class="text-[11px] font-mono text-neon-red">{$t('vd.unreachable')}</div>
      {:else if livenessUp && healthReason}
        <div class="text-[11px] font-mono text-neon-amber">{$t('vd.serviceUp', { reason: healthReason })}</div>
      {/if}
      <div class="flex flex-wrap gap-1 items-center">
        {#each vm.tags as tag}<span class="hud-label border border-hud-line rounded px-1.5 py-0.5">{tag}</span>{/each}
        <span class="hud-label border rounded px-1.5 py-0.5 {vm.ai_enabled ? 'text-neon-cyan border-neon-cyan/40' : 'text-hud-dim border-hud-line'}" title={$t('vd.aiAccessHint')}>{vm.ai_enabled ? $t('vd.aiOn') : $t('vd.aiOff')}</span>
        <span class="hud-label border rounded px-1.5 py-0.5 inline-flex items-center gap-1 {cred.has_secret ? 'text-neon-green border-neon-green/30' : 'text-hud-dim border-hud-line'}" title={$t('vd.sshCreds')}>{#if cred.has_secret}<Lock size={10} cls="text-neon-green" />{/if}{cred.has_secret ? $t('vd.credsSet') : $t('vd.credsNone')}</span>
      </div>
    </div>

    <!-- Edit (fields + creds) — at the top so it's visible above terminal -->
    {#if editMode}
      <section class="hud-panel p-4 space-y-4">
        <div>
          <div class="hud-label text-neon-cyan mb-2">{$t('vd.vmFields')}</div>
          <div class="grid grid-cols-2 gap-3">
            <label class="block space-y-1"><span class="hud-label">{$t('vd.name')}</span><input class="hud-input" bind:value={edit.name} /></label>
            <label class="block space-y-1"><span class="hud-label">{$t('vd.hostname')}</span><input class="hud-input" bind:value={edit.hostname} /></label>
            <label class="block space-y-1"><span class="hud-label">{$t('vd.ip')}</span><input class="hud-input" bind:value={edit.ip} /></label>
            <label class="block space-y-1"><span class="hud-label">{$t('vd.sshPort')}</span><input class="hud-input font-mono" type="number" bind:value={edit.port_ssh} /></label>
            <label class="block space-y-1 col-span-2"><span class="hud-label">{$t('vd.tags')}</span><input class="hud-input" bind:value={edit.tags} /></label>
            <label class="block space-y-1 col-span-2"><span class="hud-label">{$t('vd.notes')}</span><textarea class="hud-input resize-none" rows="2" bind:value={edit.notes}></textarea></label>
          </div>
          <div class="flex items-center gap-2 mt-3"><button class="hud-btn hud-btn-primary" on:click={saveEdit}>{$t('vd.saveVm')}</button><button class="hud-btn" on:click={archiveVm}>{$t('vd.archive')}</button><button class="hud-btn !text-neon-red border-neon-red/40" on:click={deleteVm}>{$t('g.delete')}</button>{#if editMsg}<span class="text-xs font-mono text-neon-red">{editMsg}</span>{/if}</div>
          <label class="flex items-center gap-2 mt-3 cursor-pointer select-none">
            <input type="checkbox" class="accent-neon-cyan" checked={vm.ai_enabled} on:change={toggleAIAccess} />
            <span class="hud-label">{$t('vd.aiAccess', { state: vm.ai_enabled ? $t('vd.aiGranted') : $t('vd.aiOffState') })}</span>
            <span class="text-[11px] text-hud-dim">{$t('vd.aiAccessHint')}</span>
          </label>
        </div>
        <div class="border-t border-hud-line pt-3">
          <div class="flex items-center gap-2 mb-2"><span class="hud-label text-neon-cyan">{$t('vd.sshCreds')}</span>{#if cred.has_secret}<span class="hud-label text-neon-green border border-neon-green/30 rounded px-1.5">{$t('vd.credsSet')}</span>{:else}<span class="hud-label text-hud-dim border border-hud-line rounded px-1.5">{$t('vd.credsNone')}</span>{/if}</div>
          {#if !twofaOn}
            <div class="text-[11px] font-mono text-neon-amber border border-neon-amber/30 rounded p-2 bg-neon-amber/5 mb-2">
              {$t('vd.2faRequiredCred')} <button type="button" class="text-neon-cyan underline cursor-pointer" on:click={() => gotoSettings.set(true)}>{$t('vd.2faGoSettings')}</button>
            </div>
          {/if}
          <div class="grid grid-cols-3 gap-2">
            <input class="hud-input" placeholder={$t('vd.sshUserPh')} bind:value={cred.ssh_user} />
            <select class="hud-input" bind:value={cred.auth_type} disabled={!twofaOn}><option value="password">password</option><option value="key">key</option><option value="agent">agent</option></select>
            {#if cred.auth_type === 'key'}
              <textarea class="hud-input font-mono resize-none" rows="2" placeholder={credPH} bind:value={cred.secret} disabled={!twofaOn}></textarea>
            {:else}
              <input class="hud-input" type="password" placeholder={credPH} bind:value={cred.secret} disabled={!twofaOn} />
            {/if}
          </div>
          {#if cred.auth_type === 'key'}
            <input class="hud-input mt-2" type="password" placeholder={$t('vd.keyPassph')} bind:value={cred.key_passphrase} disabled={!twofaOn} />
          {/if}
          <input class="hud-input mt-2" type="password" placeholder={$t('vd.sudoPw')} bind:value={cred.sudo_password} disabled={!twofaOn} />
          {#if cred.has_sudo && !cred.sudo_password}<span class="hud-label text-neon-green mt-1 inline-block">{$t('vd.sudoSet')}</span>{/if}
          <div class="flex items-center gap-2 mt-2"><button class="hud-btn hud-btn-primary" on:click={saveCred} disabled={cred.busy || !twofaOn}>{cred.busy ? $t('g.saving') : $t('vd.saveProbe')}</button><button class="hud-btn" on:click={clearCred} disabled={cred.busy || !cred.has_secret}>{$t('vd.clear')}</button>{#if cred.msg}<span class="text-xs font-mono {cred.ok ? 'text-neon-green' : 'text-neon-amber'}">{cred.msg}</span>{/if}</div>
          {#if validate.kind}
            <div class="text-xs font-mono text-neon-red mt-2">
              {$t('vd.connCheck')} <span class="uppercase">{validate.kind}</span> {#if validate.kind === 'no_credentials'}{$t('vd.errSecret')}{:else if validate.kind === 'auth_failed'}{$t('vd.errAuth')}{:else if validate.kind === 'host_key_changed'}— <button class="hud-btn !px-2 !py-0.5" on:click={resetHostKey}>{$t('vd.resetHostKey')}</button>{/if}
              {#if validate.detail}<div class="text-hud-dim mt-1 break-all">{validate.detail}</div>{/if}
            </div>
          {/if}
        </div>
      </section>
    {/if}

    <!-- Plane A divider: monitoring (no credentials) -->
    <div class="flex items-center gap-2 pt-1">
      <span class="hud-label text-neon-cyan">{$t('vd.planeA')}</span>
      <span class="text-[10px] text-hud-dim">// {$t('vd.planeAHint')}</span>
      <span class="flex-1 h-px bg-hud-line"></span>
    </div>

    <!-- battery + ip/info: equal-width narrow panels (side by side) so content is dense, not spread wide -->
    <div class="grid grid-cols-2 gap-2">
    <!-- Liveness // probe: battery (auto snapshot) + manual probe (collapsible) -->
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">{$t('vd.statusBattery')}</span>
        {#if !battery.busy && battery.probes.length}
          <span class="hud-label ml-auto uppercase {livenessUp ? 'text-neon-green' : 'text-neon-red'}">{livenessUp ? $t('vd.up') : $t('vd.down')} · <span class="normal-case">{livenessEvidence}</span></span>
        {/if}
        <button class="hud-btn !py-0.5" on:click={() => loadBattery(vmId)} disabled={battery.busy}>{battery.busy ? '…' : '↻'}</button>
        <div class="relative inline-flex">
          <button class="hud-btn inline-flex items-center justify-center leading-none !py-1 !px-2 {bellOn ? '!bg-neon-green/15 !border-neon-green/50' : ''}" on:click={() => (bellOpen ? (bellOpen = false) : openBell())} disabled={vmAlertBusy} title={bellTitle}>
            {#if vmAlertBusy}…{:else}<Bell size={13} cls={bellOn ? 'text-neon-green' : 'text-neon-green/40'} />{/if}
          </button>
          {#if bellOpen}
            <div class="fixed inset-0 z-[65]" on:click={() => (bellOpen = false)} on:contextmenu|preventDefault={() => (bellOpen = false)}></div>
            <div class="absolute right-0 mt-1 w-64 hud-panel p-2 z-[70] space-y-1">
              <div class="hud-label text-neon-cyan">{$t('vd.alertChannels')}</div>
              {#if $coverage.channels.length}
                <div class="max-h-48 overflow-auto space-y-0.5">
                  {#each $coverage.channels as c (c.id)}
                    <label class="flex items-center gap-2 text-xs font-mono cursor-pointer px-1 py-0.5 hover:bg-hud-panel2 rounded">
                      <input type="checkbox" class="accent-neon-green" checked={pickerSel.has(c.id)} on:change={(e) => { if (e.currentTarget.checked) pickerSel = new Set([...pickerSel, c.id]); else { const n = new Set(pickerSel); n.delete(c.id); pickerSel = n } }} />
                      <span class="text-neon-cyan uppercase w-16">{c.type}</span>
                      <span class="text-emerald-100 truncate">{c.name}</span>
                    </label>
                  {/each}
                </div>
              {:else}
                <div class="text-[11px] text-hud-dim">{$t('mx.noExternalChannel')} <button type="button" class="text-neon-cyan underline" on:click={() => gotoSettings.set(true)}>{$t('mx.configure')} →</button></div>
              {/if}
              <div class="flex items-center gap-1 pt-1">
                <button class="hud-btn hud-btn-primary !py-0.5 !text-[10px]" on:click={savePicker} disabled={vmAlertBusy}>{$t('g.save')}</button>
                {#if bellOn}<button class="hud-btn !text-neon-red border-neon-red/40 !py-0.5 !text-[10px]" on:click={turnOffAlert} disabled={vmAlertBusy}>{$t('g.off')}</button>{/if}
                <button class="hud-btn !py-0.5 !text-[10px] ml-auto" on:click={() => (bellOpen = false)}>{$t('g.cancel')}</button>
              </div>
            </div>
          {/if}
        </div>
      </div>
      {#if vmAlertMsg}<div class="text-[10px] text-neon-amber font-mono">{vmAlertMsg}</div>{/if}
      {#if battery.busy}
        <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('vd.probingBattery')}</div>
      {:else if battery.err}
        <div class="text-xs font-mono text-neon-red">{battery.err}</div>
      {:else}
        <div class="flex flex-wrap gap-1.5">
          {#each battery.probes as p}
            <div class="flex items-center gap-1 border border-hud-line rounded px-1.5 py-0.5 text-xs font-mono" title={probeHint(p.name)}>
              <span class="{p.status === 'ok' ? 'text-neon-green' : 'text-neon-red'}">{p.status === 'ok' ? '✓' : '✗'}</span>
              <span class="text-hud-dim">{p.name === 'ssh' ? 'ssh:' + (vm.port_ssh || 22) : p.name}</span>
              {#if p.status === 'ok'}<span class="text-hud-dim">{Number(p.latency_ms).toFixed(0)}ms</span>{/if}
            </div>
          {/each}
        </div>
        <div class="text-[11px] text-hud-dim">{$t('vd.batteryHint')}</div>
        {#if !battery.probes.length}<div class="hud-label text-hud-dim">{$t('vd.noProbes')}</div>{/if}
      {/if}

      <!-- Manual probe: a single checker (tcp/http/tls/whois) with a custom port/url, on demand -->
      <details class="border-t border-hud-line pt-2 mt-1">
        <summary class="hud-label text-hud-dim cursor-pointer select-none">{$t('vd.toolsProbe')}</summary>
        <div class="grid grid-cols-[auto_1fr_auto] gap-2 items-center mt-2">
          <select class="hud-input" bind:value={diag.check_type}>
            {#each DIAG_TYPES as dt}<option value={dt}>{dt}</option>{/each}
          </select>
          <input class="hud-input" placeholder={needsParam ? (diag.check_type === 'http' ? 'http://host/path' : 'port') : '—'} bind:value={diag.param} disabled={!needsParam} />
          <button class="hud-btn hud-btn-primary" on:click={runDiag} disabled={diag.busy}>{diag.busy ? '…' : $t('g.run')}</button>
        </div>
        {#if diag.msg}<div class="text-xs font-mono text-neon-red">{diag.msg}</div>{/if}
        {#if diag.res}
          <div class="border border-hud-line rounded px-2 py-1 text-xs font-mono flex items-center gap-2 mt-2">
            <span class="hud-label {diag.res.status === 'ok' ? 'text-neon-green' : diag.res.status === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{diag.res.status}</span>
            <span class="text-hud-dim">{Number(diag.res.latency_ms || 0).toFixed(1)}ms</span>
            <span class="text-emerald-200/70 min-w-0 break-words">{diag.res.message}</span>
          </div>
        {/if}
      </details>
    </section>

    <!-- IP info (GeoIP + ASN + PTR) — Plane A, keyless -->
    {#if vm.ip}
      <section class="hud-panel p-2.5 space-y-1.5">
        <div class="flex items-center gap-2">
          <span class="hud-label text-neon-cyan">{$t('vd.ipInfo')}</span>
          <span class="text-xs text-hud-dim font-mono truncate ml-1">{vm.ip}</span>
          <button class="hud-btn !py-0.5 ml-auto" on:click={() => loadIPInfo(vmId)} disabled={ipinfo.busy}>{ipinfo.busy ? '…' : '↻'}</button>
        </div>
        {#if ipinfo.busy}
          <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('vd.resolvingGeo')}</div>
        {:else if ipinfo.err}
          <div class="text-xs font-mono text-neon-red">{ipinfo.err}</div>
        {:else if ipinfo.data}
          <div class="text-xs font-mono space-y-1">
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">{$t('vd.location')}</span> {ipinfo.data.country || '—'}{ipinfo.data.city ? ' · ' + ipinfo.data.city : ''}{ipinfo.data.country_code ? ' (' + ipinfo.data.country_code + ')' : ''}</div>
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">asn</span> {ipinfo.data.asn || '—'}</div>
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">{$t('vd.isp')}</span> {ipinfo.data.isp || ipinfo.data.org || '—'}</div>
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">tz</span> {ipinfo.data.timezone || '—'}</div>
            <div class="min-w-0 break-words"><span class="hud-label text-hud-dim">ptr</span> {ipinfo.data.ptr || '—'}</div>
          </div>
          {#if ipinfo.data.geo_error}<div class="text-[11px] font-mono text-neon-amber">geo: {ipinfo.data.geo_error}</div>{/if}
        {/if}
      </section>
    {/if}
    </div>

    <!-- Ports // exposed (external scan, Plane A, no creds) -->
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
          <span class="hud-label text-neon-cyan">{$t('vd.portsExposed')}</span>
          <span class="text-xs text-hud-dim font-mono ml-1">{$t('vd.portsCount', { open: portscan.ports.filter((p) => p.open).length, scanned: portscan.ports.length })}</span>
          <button class="hud-btn !py-0.5 ml-auto" on:click={() => loadPortScan(vmId)} disabled={portscan.busy} title={$t('vd.refreshStd')}>{portscan.busy ? '…' : '↻'}</button>
          <button class="hud-btn !py-0.5" on:click={() => (deepscan.show = true)} disabled={deepscan.busy} title={$t('vd.deepHint')}>⌖ {$t('vd.deepScan')}</button>
        </div>
        {#if portscan.busy}
          <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('vd.scanningPorts')}</div>
        {:else if portscan.err}
          <div class="text-xs font-mono text-neon-red">{portscan.err}</div>
        {:else}
          <div class="flex flex-wrap gap-1.5">
            {#each portscan.ports as p}
              <div class="flex items-center gap-1 border rounded px-1.5 py-0.5 text-xs font-mono {p.open ? 'border-neon-green/40 bg-neon-green/5' : 'border-hud-line opacity-50'}" title={p.open ? $t('vd.openSvc', { service: p.service }) : $t('vd.closed')}>
                <span class="{p.open ? 'text-neon-green' : 'text-hud-dim'}">{p.open ? '●' : '○'}</span>
                <span class={p.open ? 'text-emerald-100' : 'text-hud-dim'}>{p.port}</span>
                <span class="text-hud-dim">{p.service}</span>
              </div>
            {/each}
          </div>
          <div class="text-[11px] text-hud-dim">{$t('vd.portsHint')}</div>
        {/if}

        <!-- Deep scan results (wide-range TCP; finds ports the standard 25 miss) -->
        {#if deepscan.busy}
          <div class="border-t border-hud-line pt-1.5 hud-label text-neon-amber"><span class="hud-spinner"></span> ⌖ {$t('vd.deepRunning', { scope: deepscan.scope })}</div>
        {:else if deepscan.err}
          <div class="border-t border-hud-line pt-1.5 text-xs font-mono text-neon-red">⌖ {deepscan.err}</div>
        {:else if deepscan.open.length}
          <div class="border-t border-hud-line pt-1.5 space-y-1">
            <div class="hud-label text-neon-amber">⌖ {$t('vd.deepResult', { open: deepscan.open.length, scope: deepscan.scope })}</div>
            <div class="flex flex-wrap gap-1.5">
              {#each deepscan.open as p}
                <div class="flex items-center gap-1 border border-neon-green/40 bg-neon-green/5 rounded px-1.5 py-0.5 text-xs font-mono" title={p.service || $t('vd.unknownSvc')}>
                  <span class="text-neon-green">●</span>
                  <span class="text-emerald-100">{p.port}</span>
                  <span class="text-hud-dim">{p.service}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}
    </section>

    <!-- Deep-scan modal: scope choice + ban/duration warning -->
    {#if deepscan.show}
      <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" on:click|self={() => (deepscan.show = false)}>
        <div class="hud-panel p-4 space-y-3 max-w-sm w-full">
          <div class="hud-label text-neon-cyan">⌖ {$t('vd.deepTitle')}</div>
          <p class="text-xs text-hud-dim">{$t('vd.deepDesc')}</p>
          <div class="space-y-2">
            <label class="flex items-center gap-2 cursor-pointer select-none">
              <input type="radio" class="accent-neon-cyan" name="dscope" value="fast" checked={deepscan.scope === 'fast'} on:change={() => (deepscan.scope = 'fast')} />
              <span class="text-xs"><span class="text-emerald-100">{$t('vd.deepFast')}</span> — {$t('vd.deepFastHint')}</span>
            </label>
            <label class="flex items-center gap-2 cursor-pointer select-none">
              <input type="radio" class="accent-neon-cyan" name="dscope" value="full" checked={deepscan.scope === 'full'} on:change={() => (deepscan.scope = 'full')} />
              <span class="text-xs"><span class="text-emerald-100">{$t('vd.deepFull')}</span> — {$t('vd.deepFullHint')}</span>
            </label>
          </div>
          <div class="text-[11px] text-neon-amber border border-neon-amber/30 rounded px-2 py-1">⚠ {$t('vd.deepWarn')}</div>
          <div class="flex items-center gap-2">
            <button class="hud-btn hud-btn-primary" on:click={runDeepScan}>⌖ {$t('vd.deepGo')}</button>
            <button class="hud-btn" on:click={() => (deepscan.show = false)}>{$t('g.cancel')}</button>
          </div>
        </div>
      </div>
    {/if}

    <!-- Security // exposures (curated exposure scan, Plane A, no creds) -->
    {#if vm.ip}
      <section class="hud-panel p-2.5 space-y-1.5">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="hud-label text-neon-cyan">{$t('vd.exposures')}</span>
          {#if !exposures.busy && exposures.findings.length}
            <span class="hud-label text-hud-dim font-mono ml-1">{exposures.findings.filter(f => f.severity === 'critical').length} critical · {exposures.findings.length} total</span>
          {/if}
          <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={() => loadExposures(vmId)} disabled={exposures.busy}>{exposures.busy ? '…' : $t('g.scan')}</button>
        </div>
        {#if exposures.busy}
          <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('vd.exposuresScanning')}</div>
        {:else if exposures.err}
          <div class="text-xs font-mono text-neon-red">{exposures.err}</div>
        {:else if exposures.findings.length}
          <div class="text-[11px] text-hud-dim">{$t('vd.exposuresHint')}</div>
          <div class="space-y-1.5">
            {#each exposures.findings as f (f.id)}
              <div class="border-l-2 pl-2 py-1 {f.severity === 'critical' ? 'border-neon-red bg-neon-red/5' : f.severity === 'high' ? 'border-neon-amber bg-neon-amber/5' : 'border-hud-line'}">
                <div class="flex items-center gap-2">
                  <span class="hud-label uppercase {f.severity === 'critical' ? 'text-neon-red' : f.severity === 'high' ? 'text-neon-amber' : 'text-hud-dim'}">{f.severity}</span>
                  <span class="text-xs font-mono text-emerald-100">{f.title}</span>
                </div>
                <div class="text-[11px] text-hud-dim mt-0.5">{f.detail}</div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="hud-label text-neon-green">{$t('vd.exposuresNone')}</div>
        {/if}
      </section>
    {/if}

    <!-- Plane B divider: management (requires SSH credentials) -->
    <div class="flex items-center gap-2 pt-1">
      <span class="hud-label text-neon-amber">{$t('vd.planeB')}</span>
      <span class="text-[10px] text-hud-dim">// {$t('vd.planeBHint')}</span>
      <span class="flex-1 h-px bg-hud-line"></span>
    </div>

    <!-- System profile (inventory from cred-save probe) -->
    {#if system}
      <section class="hud-panel p-2.5 space-y-1.5">
        <div class="flex items-center gap-2">
          <div class="hud-label text-neon-cyan">{$t('vd.systemProfile')}</div>
          <button class="hud-btn !py-0.5 ml-auto" on:click={refreshProfile} disabled={profileBusy}>{profileBusy ? '…' : $t('g.refresh')}</button>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.os')}</span> {system.os || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.kernel')}</span> {system.kernel || '—'} {system.arch}</div>
          <div class="truncate col-span-2"><span class="hud-label text-hud-dim">{$t('vd.cpu')}</span> {system.cpu_model || '—'}</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.ram')}</span> {system.mem_total_mb} MB</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.swap')}</span> {system.swap_total_mb} MB</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.packages')}</span> {system.packages || '—'}</div>
          <div><span class="hud-label text-hud-dim">{$t('vd.services')}</span> {system.services || '—'}</div>
          <div class="col-span-2"><span class="hud-label text-hud-dim">{$t('vd.uptime')}</span> {system.uptime || '—'}</div>
        </div>
        {#if system.ports?.length}
          <div class="text-xs font-mono"><span class="hud-label text-hud-dim">{$t('vd.listeningPorts')}</span> <span class="text-emerald-200">{system.ports.join(', ')}</span></div>
        {/if}
        {#if system.docker?.length}
          <details class="text-xs font-mono" open>
            <summary class="hud-label text-hud-dim cursor-pointer">{$t('vd.dockerContainers', { up: system.docker.filter((c) => c.up).length, n: system.docker.length })}</summary>
            <div class="space-y-1.5 mt-1.5">
              {#each system.docker as c}
                <div class="pl-1">
                  <div class="flex items-center gap-2">
                    <span class={c.up ? 'text-neon-green' : 'text-neon-red'} title={c.status}>{c.up ? '●' : '○'}</span>
                    <span class="text-emerald-200/90 truncate">{c.name || '—'}</span>
                    {#if c.image}<span class="text-hud-dim truncate">// {c.image}</span>{/if}
                    <span class="text-hud-dim ml-auto whitespace-nowrap text-[10px]">{c.status}</span>
                  </div>
                  {#if c.ports}<div class="text-hud-dim/70 pl-5 text-[10px] truncate">{c.ports}</div>{/if}
                </div>
              {/each}
            </div>
          </details>
        {/if}
        {#if system.services_list?.length}
          <details class="text-xs font-mono">
            <summary class="hud-label text-hud-dim cursor-pointer">{$t('vd.runningServices', { n: system.services_list.length })}</summary>
            <div class="flex flex-wrap gap-1 mt-1">{#each system.services_list as svc}<span class="text-emerald-200/70 border border-hud-line rounded px-1">{svc}</span>{/each}</div>
          </details>
        {/if}
        {#if system.packages != null}
          <details class="text-xs font-mono" on:open={loadPackages}>
            <summary class="hud-label text-hud-dim cursor-pointer">{$t('vd.packagesN', { n: system.packages })}</summary>
            {#if packagesList === null}
              <div class="hud-label text-neon-cyan mt-1"><span class="hud-spinner"></span> {$t('g.loading')}</div>
            {:else if packagesList.length}
              <div class="flex flex-wrap gap-1 mt-1 max-h-32 overflow-auto">{#each packagesList as p}<span class="text-emerald-200/60 border border-hud-line rounded px-1">{p}</span>{/each}</div>
            {:else}
              <div class="hud-label text-hud-dim mt-1">{$t('vd.noPackageList')}</div>
            {/if}
          </details>
        {/if}
      </section>
    {/if}

    <!-- Logs // errors (journalctl priority=err, Plane B over SSH) -->
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">{$t('vd.logsErrors')}</span>
        {#each ['1h', '24h', '7d'] as r}
          <button class="hud-btn !py-0.5 {errors.range === r ? 'hud-btn-primary' : ''}" on:click={() => { errors.range = r }}>{r}</button>
        {/each}
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadErrors} disabled={errors.busy}>{errors.busy ? '…' : $t('g.scan')}</button>
      </div>
      {#if errors.err}
        <div class="text-xs font-mono text-neon-red">{errors.err}{#if errors.kind === 'no_credentials'}<span class="text-hud-dim"> {$t('vd.setCredsHint')}</span>{:else if errors.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>{$t('vd.resetHostKey')}</button>{/if}</div>
      {:else if errors.data}
        <div class="text-xs font-mono text-hud-dim">{$t('vd.errorsCount', { n: errors.data.count, window: errors.data.window })}</div>
        {#if errors.data.entries?.length}
          <div class="space-y-1 max-h-56 overflow-auto">
            {#each errors.data.entries as e}
              <div class="text-xs font-mono border-l-2 border-neon-red/40 pl-2">
                <span class="text-hud-dim">{e.ts.slice(11)}</span> <span class="text-neon-amber">{e.unit}</span> <span class="text-emerald-200/70 break-all">{e.msg}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="hud-label text-neon-green">{$t('vd.noErrors')}</div>
        {/if}
      {/if}
    </section>

    <!-- Updates // available (apt simulate, Plane B over SSH) -->
    {#if cred.has_secret}
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">{$t('vd.updatesAvail')}</span>
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadUpdates} disabled={updates.busy}>{updates.busy ? '…' : $t('g.check')}</button>
      </div>
      {#if updates.err}
        <div class="text-xs font-mono text-neon-red">{updates.err}{#if updates.kind === 'no_credentials'}<span class="text-hud-dim"> {$t('vd.setCredsHint')}</span>{/if}</div>
      {:else if updates.data}
        <div class="flex items-center gap-3 flex-wrap">
          {#if updates.data.count === 0}
            <span class="hud-label text-neon-green">{$t('vd.upToDate')}</span>
          {:else}
            <span class="text-xs font-mono {updates.data.security_count > 0 ? 'text-neon-red' : 'text-neon-amber'}">{$t('vd.upgradable', { n: updates.data.count })}{#if updates.data.security_count > 0} · {$t('vd.security', { n: updates.data.security_count })}{/if}</span>
          {/if}
          {#if updates.data.reboot_required}
            <span class="hud-label text-neon-red border border-neon-red/40 rounded px-1.5">{$t('vd.rebootRequired')}</span>
          {/if}
          <span class="hud-label text-hud-dim">{$t('vd.mgr', { name: updates.data.manager })}</span>
        </div>
        {#if updates.data.packages?.length}
          <details class="text-xs font-mono">
            <summary class="hud-label text-hud-dim cursor-pointer">{$t('vd.packagesN', { n: updates.data.packages.length })}</summary>
            <div class="flex flex-wrap gap-1 mt-1 max-h-40 overflow-auto">{#each updates.data.packages as p}<span class="border rounded px-1 {p.security ? 'text-neon-red border-neon-red/40' : 'text-emerald-200/70 border-hud-line'}" title={p.version + ' · ' + p.suite}>{p.name}{#if p.security} ⚡{/if}</span>{/each}</div>
          </details>
        {/if}
      {/if}
    </section>
    {/if}

    <!-- Sites // vhosts (nginx/apache config, Plane B over SSH) — only when SSH creds exist -->
    {#if cred.has_secret}
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">{$t('vd.sitesVhosts')}</span>
        <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={loadVHosts} disabled={vhosts.busy}>{vhosts.busy ? '…' : $t('g.scan')}</button>
      </div>
      {#if vhosts.err}
        <div class="text-xs font-mono text-neon-red">{vhosts.err}{#if vhosts.kind === 'no_credentials'}<span class="text-hud-dim"> {$t('vd.setCredsHint')}</span>{/if}</div>
      {:else if vhosts.data}
        <div class="text-xs font-mono text-hud-dim">{$t('vd.server', { name: vhosts.data.server })}{#if vhosts.data.listening?.length}<span class="ml-2">{$t('vd.listening')} {vhosts.data.listening.join(', ')}</span>{/if}{#if !vhosts.data.root}<span class="ml-2 text-neon-amber">{$t('vd.nonRoot')}</span>{/if}</div>
        {#if vhosts.data.sites?.length}
          <div class="flex flex-wrap gap-1">{#each vhosts.data.sites as s}<span class="text-emerald-200/80 border border-hud-line rounded px-1.5 py-0.5 text-xs font-mono">{s.name}{#if s.port}<span class="text-hud-dim">:{s.port}</span>{/if}</span>{/each}</div>
        {:else if vhosts.data.server === 'unknown'}
          <div class="hud-label text-neon-amber">{$t('vd.vhostsNonRoot')}</div>
        {:else if vhosts.data.server !== 'none'}
          <div class="hud-label text-neon-amber">{$t('vd.vhostsNoConfig', { server: vhosts.data.server })}</div>
        {:else}
          <div class="hud-label text-hud-dim">{$t('vd.noWebServer')}</div>
        {/if}
      {/if}
    </section>
    {/if}

    <!-- Site info (HTTP headers + security + CMS, Plane A keyless) — only when a web port answers -->
    {#if vm.ip && (battery.busy || batteryWebOk)}
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2">
        <span class="hud-label text-neon-cyan">{$t('vd.siteInfo')}</span>
        <input class="hud-input text-xs flex-1 min-w-0" bind:value={siteinfo.url} placeholder="http://host/" />
        <button class="hud-btn hud-btn-primary !py-0.5" on:click={loadSiteInfo} disabled={siteinfo.busy}>{siteinfo.busy ? '…' : $t('g.scan')}</button>
      </div>
      {#if siteinfo.err}
        <div class="text-xs font-mono text-neon-red">{siteinfo.err}</div>
      {:else if siteinfo.data}
        <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs font-mono">
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.status')}</span> {siteinfo.data.status || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.serverLbl')}</span> {siteinfo.data.server || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.powered')}</span> {siteinfo.data.powered_by || '—'}</div>
          <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.cms')}</span> <span class="text-neon-cyan">{siteinfo.data.cms || '—'}{#if siteinfo.data.cms_version}<span class="text-hud-dim"> {siteinfo.data.cms_version}</span>{/if}</span></div>
        </div>
        <div class="text-xs font-mono">
          <span class="hud-label text-hud-dim">{$t('vd.securityLbl')}</span>
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
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">{$t('vd.metricsHistory')}</span>
        <span class="hud-label text-hud-dim ml-auto">{$t('vd.sshPull')}</span>
        <button class="hud-btn !py-0.5" on:click={toggleMetrics}>{vm.metrics_enabled ? $t('vd.metricsOn') : $t('vd.metricsOff')}</button>
      </div>
      {#if vm.metrics_enabled}
        <div class="flex items-center gap-2 flex-wrap">
          {#each ['1h', '24h', '7d'] as r}
            <button class="hud-btn !py-0.5 {metricsRange === r ? 'hud-btn-primary' : ''}" on:click={() => { metricsRange = r; loadMetrics() }}>{r}</button>
          {/each}
          <button class="hud-btn !py-0.5" on:click={loadMetrics} disabled={metricsBusy}>{metricsBusy ? '…' : '↻'}</button>
          {#if metricsTs}<span class="text-[10px] font-mono text-hud-dim ml-auto">{$t('vd.last')} {metricsTs.slice(11, 19)}</span>{/if}
        </div>
        {#if metricsErr}<div class="text-xs font-mono text-neon-red">{metricsErr}</div>{/if}
        <div class="grid grid-cols-2 gap-2">
          <MetricsChart label={$t('vd.cpu')} unit="%" data={series.cpu_pct} decimals={0} color="#f97316" />
          <MetricsChart label={$t('vd.memory')} unit="MB" data={series.mem_used_mb} color="#22d3ee" />
          <MetricsChart label={$t('vd.swap')} unit="MB" data={series.swap_used_mb} color="#a78bfa" />
          <MetricsChart label={$t('vd.disk')} unit="GB" data={series.disk_used_gb} decimals={1} color="#22c55e" />
          <MetricsChart label={$t('vd.load') + ' 1m'} data={series.load1} decimals={2} color="#eab308" />
          <MetricsChart label="tcp conns" data={series.tcp_conns} color="#38bdf8" />
          <MetricsChart label="net rx" unit="KB/s" data={series.net_rx_kbps} decimals={1} color="#34d399" />
          <MetricsChart label="net tx" unit="KB/s" data={series.net_tx_kbps} decimals={1} color="#f472b6" />
        </div>
      {:else}
        <p class="text-xs text-hud-dim">{$t('vd.metricsHint')}</p>
      {/if}
    </section>

    <!-- Live (interactive terminal) + one-shot snapshot (only when metrics history is off) -->
    <section class="hud-panel p-2.5 space-y-1.5">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">{$t('vd.liveTerminal')}</span>
        {#if !vm.metrics_enabled}
          <button class="hud-btn hud-btn-primary !py-0.5 ml-auto" on:click={runSnapshot} disabled={snap.busy}>{snap.busy ? '…' : $t('vd.snapshot')}</button>
        {/if}
        <button class="hud-btn !py-0.5 {!vm.metrics_enabled ? '' : 'ml-auto'}" on:click={() => { showTerm = !showTerm; termNote = { msg: '', kind: '' } }}>{showTerm ? $t('g.close') : $t('vd.terminal')}</button>
      </div>

      {#if !vm.metrics_enabled}
        {#if snap.err}
          <div class="text-xs font-mono text-neon-red">
            {snap.err}
            {#if snap.kind === 'no_credentials'}<span class="text-hud-dim"> {$t('vd.setCredsHint')}</span>{/if}
            {#if snap.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>{$t('vd.resetHostKey')}</button>{/if}
          </div>
        {/if}
        {#if snap.data}
          <div class="space-y-1.5">
            <div>
              <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>{$t('vd.memory')}</span><span>{snap.data.mem_used_mb}/{snap.data.mem_total_mb} MB</span></div>
              <div class="h-1.5 bg-hud-line rounded"><div class="h-full bg-neon-cyan rounded" style="width:{memPct}%"></div></div>
            </div>
            <div>
              <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>{$t('vd.disk')}</span><span>{Number(snap.data.disk_used_gb).toFixed(1)}/{Number(snap.data.disk_total_gb).toFixed(1)} GB</span></div>
              <div class="h-1.5 bg-hud-line rounded"><div class="h-full {diskPct > 85 ? 'bg-neon-red' : 'bg-neon-green'} rounded" style="width:{diskPct}%"></div></div>
            </div>
            <div class="grid grid-cols-3 gap-2 text-xs font-mono">
              <div><span class="hud-label text-hud-dim">{$t('vd.load')}</span> <span class="text-neon-green">{snap.data.load1?.toFixed(2)}</span> <span class="text-hud-dim">{snap.data.load5?.toFixed(2)}/{snap.data.load15?.toFixed(2)}</span></div>
              <div><span class="hud-label text-hud-dim">{$t('vd.cpus')}</span> <span>{snap.data.cpu_count}</span></div>
              <div class="truncate"><span class="hud-label text-hud-dim">{$t('vd.uptime')}</span> <span class="text-hud-dim">{snap.data.uptime}</span></div>
            </div>
          </div>
        {:else if !snap.err}
          <p class="text-xs text-hud-dim">{$t('vd.snapshotHint')}</p>
        {/if}
      {:else}
        <p class="text-xs text-hud-dim">{$t('vd.liveMetricsHint')}</p>
      {/if}

      {#if showTerm}
        <div class="space-y-2">
          {#key termKey}
            <Terminal vmId={vmId} on:error={onTermError} />
          {/key}
          {#if termNote.msg}
            <div class="text-xs font-mono text-neon-red">
              {termNote.msg}
              {#if termNote.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>{$t('vd.resetHostKey')}</button>{/if}
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <!-- Alert checks (user-configured; system liveness is auto-managed and hidden) -->
    <details class="hud-panel p-3">
      <summary class="hud-label text-neon-cyan cursor-pointer">{$t('vd.alertChecks', { n: userChecks.length })}</summary>
      <div class="text-[11px] text-hud-dim mt-1">// extra checks for alerting on specific services. Liveness (the status dot) is always-on automatically — you don't configure it here.</div>
      <div class="space-y-2 mt-2">
        {#if !userChecks.length}<div class="hud-label text-hud-dim">// none — liveness is tracked automatically. Add a check (e.g. tcp:443) to alert on a specific service.</div>{:else}
          <div class="space-y-1">
            {#each userChecks as c (c.id)}
              {@const r = results.find((x) => x.check_id === c.id)}
              <div class="flex items-center gap-2 text-xs font-mono border border-hud-line rounded px-2 py-1">
                <span class="text-emerald-200 w-24 shrink-0">{checkKey(c)}</span>
                {#if r}<span class="hud-label {r.latest_status === 'ok' ? 'text-neon-green' : r.latest_status === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{r.latest_status}</span><span class="text-hud-dim">{Number(r.latest_latency_ms).toFixed(1)}ms</span>{#if r.latest_message && r.latest_status !== 'ok'}<span class="text-neon-amber/80 truncate">{r.latest_message}</span>{/if}{:else}<span class="hud-label text-hud-dim">pending</span>{/if}
                <span class="ml-auto text-hud-dim">/{c.interval_sec}s</span>
                <button class="hud-btn !px-2 !py-0.5" on:click={() => runNow(c)} title="run now">▶</button>
                <button class="hud-btn !px-2 !py-0.5 !text-neon-red border-neon-red/40" on:click={() => removeCheck(c)} title="delete">✕</button>
              </div>
            {/each}
          </div>
        {/if}
        <div class="grid grid-cols-[auto_1fr_auto_auto] gap-2 pt-1 items-center">
          <select class="hud-input" bind:value={nc.check_type}>{#each MON_TYPES as mt}<option value={mt}>{mt}</option>{/each}</select>
          <input class="hud-input" placeholder={nc.check_type === 'http' ? 'url' : (nc.check_type === 'tcp' || nc.check_type === 'tls') ? 'port' : '—'} bind:value={nc.target} />
          <input class="hud-input w-20" type="number" placeholder="sec" bind:value={nc.interval_sec} />
          <button class="hud-btn hud-btn-primary" on:click={addCheck}>{$t('g.add')}</button>
        </div>
        {#if checkMsg}<div class="text-xs font-mono text-neon-red">{checkMsg}</div>{/if}
      </div>
    </details>
  {/if}
</div>
