<script>
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import Terminal from './Terminal.svelte'

  // region VmDetail [DOMAIN(7): UI; CONCEPT(8]: Detail; TECH(6]: svelte]
  // Plain-language detail: health (up/down + reason), ping liveness + run-now, one-shot
  // diagnostics (tcp/http/tls/whois), collapsible monitoring, SSH live metrics + terminal, edit.
  export let vmId = null

  const dispatch = createEventDispatcher()
  const DIAG_TYPES = ['tcp', 'http', 'tls', 'whois'] // ping is the liveness probe, not a diagnostic
  const MON_TYPES = ['ping', 'tcp', 'http', 'tls', 'whois']

  let vm = null
  let health = null
  let results = []
  let checks = []
  let loading = true
  let err = ''

  let editMode = false
  let edit = { name: '', hostname: '', ip: '', port_ssh: 22, tags: '', notes: '' }
  let editMsg = ''
  let cred = { ssh_user: '', auth_type: 'password', has_secret: false, secret: '', msg: '', ok: false, busy: false }

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

  $: vmId != null && loadDetail(vmId)

  async function loadDetail(id) {
    loading = true
    err = ''
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
    } catch (e) {
      err = e.message
    } finally {
      loading = false
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
      await loadDetail(vmId)
    } catch (e) {
      pingMsg = e.message
    } finally {
      pingBusy = false
    }
  }

  async function addPing() {
    try {
      await api.createCheck({ vm_id: vmId, target_type: 'vm', check_type: 'ping', interval_sec: 60 })
      await loadDetail(vmId)
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
      await loadDetail(vmId)
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
      await loadDetail(vmId)
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
      await loadDetail(vmId)
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

  async function saveCred() {
    cred.busy = true; cred.msg = ''
    try {
      await api.setVMCreds(vmId, { ssh_user: cred.ssh_user, auth_type: cred.auth_type, secret: cred.secret })
      cred.secret = ''
      const fresh = await api.getVMCreds(vmId)
      cred.has_secret = !!fresh.has_secret; cred.ssh_user = fresh.ssh_user; cred.auth_type = fresh.auth_type
      cred.msg = 'saved'; cred.ok = true
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

    <!-- Liveness: ping -->
    <section class="hud-panel p-4 space-y-2">
      <div class="hud-label text-neon-cyan">liveness&nbsp;//&nbsp;ping</div>
      {#if pingCheck}
        <div class="flex items-center gap-3">
          {#if pingResult}
            <span class="hud-label {pingResult.latest_status === 'ok' ? 'text-neon-green' : pingResult.latest_status === 'critical' ? 'text-neon-red' : 'text-neon-amber'} uppercase">{pingResult.latest_status === 'ok' ? 'up' : pingResult.latest_status === 'critical' ? 'down' : 'unknown'}</span>
            {#if pingResult.latest_status === 'ok'}<span class="text-xs text-hud-dim font-mono">{Number(pingResult.latest_latency_ms).toFixed(1)}ms</span>{/if}
            <span class="text-[11px] text-hud-dim font-mono ml-auto truncate max-w-[60%]">{pingResult.latest_message}</span>
          {:else}
            <span class="hud-label text-hud-dim">pending…</span>
          {/if}
          <button class="hud-btn hud-btn-primary !py-1" on:click={pingNow} disabled={pingBusy}>{pingBusy ? '…' : '▶ ping now'}</button>
        </div>
        {#if pingMsg}<div class="text-xs font-mono text-neon-red">{pingMsg}</div>{/if}
      {:else}
        <div class="flex items-center gap-3">
          <span class="hud-label text-hud-dim">no liveness probe</span>
          <button class="hud-btn hud-btn-primary ml-auto" on:click={addPing}>+ add ping</button>
        </div>
      {/if}
    </section>

    <!-- Diagnostics (one-shot, manual; not ping) -->
    <section class="hud-panel p-4 space-y-2">
      <div class="hud-label text-neon-cyan">diagnostics&nbsp;//&nbsp;one-shot</div>
      <div class="grid grid-cols-[auto_1fr_auto] gap-2 items-center">
        <select class="hud-input" bind:value={diag.check_type}>
          {#each DIAG_TYPES as t}<option value={t}>{t}</option>{/each}
        </select>
        <input class="hud-input" placeholder={needsParam ? (diag.check_type === 'http' ? 'http://host/path' : 'port (e.g. 22)') : '—'} bind:value={diag.param} disabled={!needsParam} />
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

    <!-- Monitoring (collapsible) -->
    <details class="hud-panel p-4">
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

    <!-- Live metrics (SSH snapshot, no agent) + interactive terminal -->
    <section class="hud-panel p-4 space-y-3">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="hud-label text-neon-cyan">live&nbsp;//&nbsp;over ssh</span>
        <button class="hud-btn hud-btn-primary !py-1 ml-auto" on:click={runSnapshot} disabled={snap.busy}>{snap.busy ? '…' : '▶ snapshot'}</button>
        <button class="hud-btn !py-1" on:click={() => { showTerm = !showTerm; termNote = { msg: '', kind: '' } }}>{showTerm ? '✕ close' : '> terminal'}</button>
      </div>

      {#if snap.err}
        <div class="text-xs font-mono text-neon-red">
          {snap.err}
          {#if snap.kind === 'no_ssh_credentials'}<span class="text-hud-dim"> — set SSH creds in ⚙ edit</span>{/if}
          {#if snap.kind === 'host_key_changed'}<button class="hud-btn !px-2 !py-0.5 ml-2" on:click={resetHostKey}>reset host key</button>{/if}
        </div>
      {/if}

      {#if snap.data}
        <div class="space-y-2">
          <div>
            <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>memory</span><span>{snap.data.mem_used_mb}/{snap.data.mem_total_mb} MB</span></div>
            <div class="h-1.5 bg-hud-line rounded"><div class="h-full bg-neon-cyan rounded" style="width:{memPct}%"></div></div>
          </div>
          <div>
            <div class="flex justify-between text-[11px] font-mono text-hud-dim"><span>disk /</span><span>{Number(snap.data.disk_used_gb).toFixed(1)}/{Number(snap.data.disk_total_gb).toFixed(1)} GB</span></div>
            <div class="h-1.5 bg-hud-line rounded"><div class="h-full {diskPct > 85 ? 'bg-neon-red' : 'bg-neon-green'} rounded" style="width:{diskPct}%"></div></div>
          </div>
          <div class="grid grid-cols-3 gap-2 text-xs font-mono pt-1">
            <div><span class="hud-label text-hud-dim">load</span> <span class="text-neon-green">{snap.data.load1?.toFixed(2)}</span> <span class="text-hud-dim">{snap.data.load5?.toFixed(2)}/{snap.data.load15?.toFixed(2)}</span></div>
            <div><span class="hud-label text-hud-dim">cpus</span> <span>{snap.data.cpu_count}</span></div>
            <div class="truncate"><span class="hud-label text-hud-dim">up</span> <span class="text-hud-dim">{snap.data.uptime}</span></div>
          </div>
        </div>
      {:else if !snap.err}
        <p class="text-xs text-hud-dim">// run a snapshot to fetch CPU / RAM / disk / load over SSH (no agent install needed).</p>
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

    <!-- Edit (fields + creds) -->
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
          <div class="flex items-center gap-2 mt-3"><button class="hud-btn hud-btn-primary" on:click={saveEdit}>save vm</button><button class="hud-btn" on:click={archiveVm}>archive</button>{#if editMsg}<span class="text-xs font-mono text-neon-red">{editMsg}</span>{/if}</div>
        </div>
        <div class="border-t border-hud-line pt-3">
          <div class="flex items-center gap-2 mb-2"><span class="hud-label text-neon-cyan">ssh credentials</span>{#if cred.has_secret}<span class="hud-label text-neon-green border border-neon-green/30 rounded px-1.5">set</span>{:else}<span class="hud-label text-hud-dim border border-hud-line rounded px-1.5">none</span>{/if}</div>
          <div class="grid grid-cols-3 gap-2">
            <input class="hud-input" placeholder="ssh user" bind:value={cred.ssh_user} />
            <select class="hud-input" bind:value={cred.auth_type}><option value="password">password</option><option value="key">key</option><option value="agent">agent</option></select>
            <input class="hud-input" type="password" placeholder={credPH} bind:value={cred.secret} />
          </div>
          <div class="flex items-center gap-2 mt-2"><button class="hud-btn hud-btn-primary" on:click={saveCred} disabled={cred.busy}>save creds</button><button class="hud-btn" on:click={clearCred} disabled={cred.busy || !cred.has_secret}>clear</button>{#if cred.msg}<span class="text-xs font-mono {cred.ok ? 'text-neon-green' : 'text-neon-red'}">{cred.msg}</span>{/if}</div>
        </div>
      </section>
    {/if}
  {/if}
</div>
