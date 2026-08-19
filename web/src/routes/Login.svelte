<script>
  import { api } from '../lib/api.js'
  import { token, user, appVersion } from '../lib/stores.js'
  import { onMount } from 'svelte'
  import { tick } from 'svelte'
  onMount(() => { api.version().then((v) => { if (v && v.version) appVersion.set(v.version) }).catch(() => {}) })
  import { t, locale } from '../lib/i18n.js'

  let username = ''
  let password = ''
  let error = ''
  let busy = false
  let twoFA = null // {pending_token} when step 2 is required
  let code = ''
  let codeInput = null

  // Autofocus the 2FA field the moment it appears: the operator reads the code off their phone
  // and types without looking back at the screen — the cursor must already be in the field.
  $: if (twoFA && codeInput) tick().then(() => codeInput.focus())

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

  // Host audit from the login page: the CLI `vmpulse doctor` prints nothing on windowsgui
  // builds, so the button is the only discoverable entry point for non-console operators.
  let docOpen = false
  let docBusy = false
  let docErr = ''
  let doc = null
  async function runDoctor() {
    docOpen = true
    docBusy = true
    docErr = ''
    doc = null
    try {
      doc = await api.doctor()
    } catch (e) {
      docErr = e.message
    } finally {
      docBusy = false
    }
  }
  // Backend findings carry stable IDs; localized title/recommendation live here (ru).
  // Technical details (uid=0, PermitRootLogin=yes…) stay as-is - machine facts, not prose.
  const DOC_SEV_RU = { critical: 'КРИТИЧНО', warn: 'ВНИМАНИЕ', minor: 'МЕЛОЧЬ', ok: 'ОК' }
  const DOC_RU = {
    svc_as_root: ['процесс запущен от рута', 'создайте непривилегированного пользователя (например, vmpulse) и запускайте сервис от него.'],
    exposed_unauth: ['открытые сервисы без авторизации', 'закройте порт или включите авторизацию; БД и docker API никогда не должны смотреть в интернет.'],
    no_firewall_public: ['не найден файрвол хоста', 'включите файрвол (ufw) и разрешите только нужные VM Pulse порты.'],
    firewall_unreadable: ['состояние файрвола нечитаемо', 'перезапустите от администратора (sudo vmpulse doctor), чтобы прочитать состояние файрвола.'],
    ssh_password_public: ['SSH принимает пароли', 'перейдите на ключи и выставьте PasswordAuthentication no.'],
    ssh_root_login: ['SSH пускает root', 'выставьте PermitRootLogin no и заходите обычным пользователем с sudo.'],
    datacenter_bind_wildcard: ['привязка на 0.0.0.0 в датацентре', 'приложение будет напрямую открыто в интернет; используйте reverse-proxy с TLS и доступом по ключам.'],
    low_disk: ['мало места на диске', 'освободите место: логи, кэши, старые бэкапы.'],
  }
  function docSev(s) { return $locale === 'ru' ? DOC_SEV_RU[s] || s : (s || '—') }
  function docTitle(f) { return ($locale === 'ru' && DOC_RU[f.id]?.[0]) || f.title }
  function docRec(f) { return ($locale === 'ru' && DOC_RU[f.id]?.[1]) || f.recommendation }
  function docSevColor(s) {
    return s === 'critical' ? 'text-neon-red border-neon-red/40' : s === 'warn' ? 'text-neon-amber border-neon-amber/40' : 'text-neon-green border-neon-green/40'
  }
</script>

<div class="min-h-full flex items-center justify-center hud-grid p-6">
  <form
    on:submit|preventDefault={twoFA ? submitTwoFA : submit}
    class="hud-panel scan w-full max-w-sm p-8 space-y-5"
  >
    <div class="space-y-1">
      <div class="flex items-center gap-2">
        <img src="/logo.png" alt="VM Pulse" class="h-8 w-8 shrink-0" />
        <div class="hud-label">// VM PULSE{#if $appVersion}<span class="text-hud-dim/70 ml-2 text-[10px] normal-case">{$appVersion}</span>{/if}</div>
      </div>
      <h1 class="text-2xl font-mono text-neon-green tracking-wide">{$t('login.title')}</h1>
      <p class="text-xs text-hud-dim">{twoFA ? $t('login.codePrompt') : $t('login.passPrompt')}</p>
    </div>

    {#if twoFA}
      <label class="block space-y-1">
        <span class="hud-label">{$t('login.codeLabel')}</span>
        <input class="hud-input" bind:value={code} bind:this={codeInput} autocomplete="one-time-code" placeholder="123456" inputmode="numeric" />
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

    <div class="pt-1 border-t border-hud-line flex items-center justify-between">
      <button type="button" class="text-[11px] font-mono text-hud-dim hover:text-neon-cyan underline" on:click={runDoctor}>{$t('login.doctor')}</button>
      <span class="text-[9px] font-mono text-hud-dim/60">read-only</span>
    </div>
  </form>


  {#if docOpen}
    <div class="fixed inset-0 z-[90] bg-black/70 flex items-center justify-center p-4" on:click={() => (docOpen = false)} on:contextmenu|preventDefault={() => (docOpen = false)}>
      <div class="hud-panel w-full max-w-xl p-5 space-y-3 max-h-[80vh] overflow-auto" on:click|stopPropagation>
        <div class="hud-label text-neon-cyan">// {$t('login.doctorTitle')}</div>
        {#if docBusy}
          <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('login.doctorBusy')}</div>
        {:else if docErr}
          <div class="text-xs font-mono text-neon-red">{docErr}</div>
          <div class="text-[11px] text-hud-dim">{$t('login.doctorFail')}</div>
        {:else if doc}
          <div class="flex items-center gap-3">
            <span class="text-xs font-mono px-2 py-1 rounded border {docSevColor(doc.verdict?.severity)} uppercase">{docSev(doc.verdict?.severity) ?? '—'}</span>
            <span class="text-xs font-mono text-hud-dim">{$t('login.docScore')}: {doc.verdict?.score ?? '?'}/100</span>
            <span class="ml-auto text-[10px] font-mono text-hud-dim">{doc.context?.distro || doc.platform}</span>
          </div>
          {#if doc.verdict?.findings?.length}
            <div class="space-y-1.5">
              {#each doc.verdict.findings as f (f.id)}
                <div class="border rounded p-2 space-y-0.5 {docSevColor(f.severity).includes('neon-red') ? 'border-neon-red/30' : docSevColor(f.severity).includes('neon-amber') ? 'border-neon-amber/30' : 'border-neon-green/30'}">
                  <div class="flex items-center gap-2">
                    <span class="text-[9px] font-mono px-1 rounded border {docSevColor(f.severity)} uppercase">{docSev(f.severity)}</span>
                    <span class="text-xs font-mono text-emerald-100">{docTitle(f)}</span>
                  </div>
                  {#if f.detail}<div class="text-[11px] text-hud-dim leading-snug">{f.detail}</div>{/if}
                  {#if f.recommendation}<div class="text-[11px] text-neon-cyan/80 leading-snug">→ {docRec(f)}</div>{/if}
                </div>
              {/each}
            </div>
          {:else}
            <div class="text-xs font-mono text-neon-green">{$t('login.doctorClean')}</div>
          {/if}
        {/if}
        <div class="flex justify-end pt-1 border-t border-hud-line">
          <button class="hud-btn !py-1" on:click={() => (docOpen = false)}>{$t('g.close')}</button>
        </div>
      </div>
    </div>
  {/if}
</div>