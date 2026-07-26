<script>
  import { api } from '../lib/api.js'
  import { token, user } from '../lib/stores.js'
  import { t } from '../lib/i18n.js'

  let username = ''
  let password = ''
  let error = ''
  let busy = false
  let twoFA = null // {pending_token} when step 2 is required
  let code = ''

  function finish(res) {
    token.set(res.token)
    user.set({ username: res.username, role: res.role })
  }

  async function submit() {
    error = ''
    busy = true
    try {
      const res = await api.login(username.trim(), password)
      if (res.requires_2fa) {
        twoFA = { pending_token: res.pending_token }
        code = ''
      } else {
        finish(res)
      }
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  async function submitTwoFA() {
    error = ''
    busy = true
    try {
      const res = await api.loginTwoFA(twoFA.pending_token, code.trim())
      twoFA = null
      finish(res)
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  function backToPassword() {
    twoFA = null
    error = ''
  }
</script>

<div class="min-h-full flex items-center justify-center hud-grid p-6">
  <form
    on:submit|preventDefault={twoFA ? submitTwoFA : submit}
    class="hud-panel scan w-full max-w-sm p-8 space-y-5"
  >
    <div class="space-y-1">
      <div class="hud-label">// VM PULSE</div>
      <h1 class="text-2xl font-mono text-neon-green tracking-wide">{$t('login.title')}</h1>
      <p class="text-xs text-hud-dim">{twoFA ? $t('login.codePrompt') : $t('login.passPrompt')}</p>
    </div>

    {#if twoFA}
      <label class="block space-y-1">
        <span class="hud-label">{$t('login.codeLabel')}</span>
        <input class="hud-input" bind:value={code} autocomplete="one-time-code" placeholder="123456" />
      </label>
    {:else}
      <label class="block space-y-1">
        <span class="hud-label">{$t('login.username')}</span>
        <input class="hud-input" bind:value={username} autocomplete="username" placeholder="owner" />
      </label>

      <label class="block space-y-1">
        <span class="hud-label">{$t('login.password')}</span>
        <input
          class="hud-input"
          type="password"
          bind:value={password}
          autocomplete="current-password"
          placeholder="••••••••"
        />
      </label>
    {/if}

    {#if error}
      <div class="text-xs text-neon-red font-mono border border-neon-red/30 rounded px-3 py-2 bg-neon-red/5">
        {error}
      </div>
    {/if}

    <button class="hud-btn hud-btn-primary w-full" disabled={busy}>
      {busy ? (twoFA ? $t('login.verifying') : $t('login.connecting')) : (twoFA ? $t('login.verify') : $t('login.connect'))}
    </button>
    {#if twoFA}
      <button type="button" class="hud-btn w-full" on:click={backToPassword}>{$t('login.back')}</button>
    {/if}
  </form>
</div>
