<script>
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  const dispatch = createEventDispatcher()

  let name = ''
  let host = ''
  let error = ''
  let busy = false
  let kind = 'server'

  async function submit() {
    error = ''
    busy = true
    try {
      // Only name + host are asked at creation: the host can be a hostname or an IP, and the SSH
      // port defaults to 22 — it's set in the server's settings once credentials are added.
      // If the host is already an IP it's also stored as `ip` (the dialer prefers IP over hostname).
      const res = await api.createVm({
        name: name.trim(),
        hostname: host.trim(),
        ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(host.trim()) ? host.trim() : '',
        port_ssh: 22,
        kind
      })
      // The backend auto-provisions a system liveness check (composite ping/ssh/web/tls) that
      // drives the fleet status dot — no need to create a check here.
      dispatch('created')
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }
</script>

<form on:submit|preventDefault={submit} class="space-y-2">
  <label class="block space-y-1">
    <span class="hud-label">{$t('addvm.name')}</span>
    <input class="hud-input w-full" bind:value={name} placeholder="web-1" />
  </label>
  <label class="block space-y-1">
    <span class="hud-label">{$t('addvm.host')}</span>
    <input class="hud-input w-full font-mono" bind:value={host} placeholder="example.com or 10.0.0.1" />
  </label>
  <label class="block space-y-1">
    <span class="hud-label">{$t('addvm.kind')}</span>
    <select class="hud-input w-full" bind:value={kind}>
      <option value="server">{$t('vmk.server')}</option>
      <option value="equipment">{$t('vmk.equipment')}</option>
    </select>
  </label>
  {#if error}
    <div class="text-xs text-neon-red font-mono border border-neon-red/30 rounded px-2 py-1.5 bg-neon-red/5">
      {error}
    </div>
  {/if}
  <button class="hud-btn hud-btn-primary w-full !py-1" disabled={busy || !name.trim() || !host.trim()}>
    {busy ? $t('addvm.deploying') : $t('addvm.submit')}
  </button>
</form>
