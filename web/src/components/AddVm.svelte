<script>
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'

  const dispatch = createEventDispatcher()

  let name = ''
  let hostname = ''
  let ip = ''
  let port = '22'
  let error = ''
  let busy = false

  async function submit() {
    error = ''
    busy = true
    try {
      const res = await api.createVm({
        name: name.trim(),
        hostname: hostname.trim(),
        ip: ip.trim(),
        port_ssh: Number(port) || 22
      })
      // Default liveness probe: ICMP ping (true up/down). If the host can't do unprivileged ICMP,
      // the checker reports "unknown" (NOT critical/down) — so a filtered ping never false-alarms.
      // SSH-port-specific monitoring can be added separately; liveness must not hinge on ssh:22.
      try {
        await api.createCheck({ vm_id: res.id, target_type: 'vm', check_type: 'ping', interval_sec: 60 })
      } catch (_) {
        /* default reachability check is optional */
      }
      dispatch('created')
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }
</script>

<form on:submit|preventDefault={submit} class="space-y-3">
  <div class="grid grid-cols-2 gap-3">
    <label class="block space-y-1">
      <span class="hud-label">name</span>
      <input class="hud-input" bind:value={name} placeholder="web-1" />
    </label>
    <label class="block space-y-1">
      <span class="hud-label">hostname</span>
      <input class="hud-input" bind:value={hostname} placeholder="host or ip" />
    </label>
    <label class="block space-y-1">
      <span class="hud-label">ip</span>
      <input class="hud-input" bind:value={ip} placeholder="10.0.0.1" />
    </label>
    <label class="block space-y-1">
      <span class="hud-label">ssh port</span>
      <input class="hud-input font-mono" type="number" bind:value={port} />
    </label>
  </div>
  {#if error}
    <div class="text-xs text-neon-red font-mono border border-neon-red/30 rounded px-3 py-2 bg-neon-red/5">
      {error}
    </div>
  {/if}
  <button class="hud-btn hud-btn-primary w-full" disabled={busy}>
    {busy ? 'deploying…' : 'add vm'}
  </button>
</form>
