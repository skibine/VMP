<script>
  import { api } from '../lib/api.js'
  import { token, user } from '../lib/stores.js'

  let username = ''
  let password = ''
  let error = ''
  let busy = false

  async function submit() {
    error = ''
    busy = true
    try {
      const res = await api.login(username.trim(), password)
      token.set(res.token)
      user.set({ username: res.username, role: res.role })
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }
</script>

<div class="min-h-full flex items-center justify-center hud-grid p-6">
  <form
    on:submit|preventDefault={submit}
    class="hud-panel scan w-full max-w-sm p-8 space-y-5"
  >
    <div class="space-y-1">
      <div class="hud-label">// VM PULSE</div>
      <h1 class="text-2xl font-mono text-neon-green tracking-wide">ACCESS&nbsp;TERMINAL</h1>
      <p class="text-xs text-hud-dim">Authenticate to enter the control plane.</p>
    </div>

    <label class="block space-y-1">
      <span class="hud-label">username</span>
      <input class="hud-input" bind:value={username} autocomplete="username" placeholder="owner" />
    </label>

    <label class="block space-y-1">
      <span class="hud-label">password</span>
      <input
        class="hud-input"
        type="password"
        bind:value={password}
        autocomplete="current-password"
        placeholder="••••••••"
      />
    </label>

    {#if error}
      <div class="text-xs text-neon-red font-mono border border-neon-red/30 rounded px-3 py-2 bg-neon-red/5">
        {error}
      </div>
    {/if}

    <button class="hud-btn hud-btn-primary w-full" disabled={busy}>
      {busy ? 'connecting…' : 'connect'}
    </button>
  </form>
</div>
