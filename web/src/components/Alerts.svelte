<script>
  // region Alerts [DOMAIN(7): UI; CONCEPT(8): Alerting; TECH(6): svelte]
  // Alerts view: delivery channels (Telegram) + rules/criteria (when to notify) + recent fired alerts.
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  let channels = []
  let rules = []
  let fired = []
  let err = ''
  // new channel form (telegram | webhook)
  let nc = { type: 'telegram', name: '', bot_token: '', chat_id: '', url: '', secret: '' }
  // new rule form
  let nr = { name: '', trigger_status: 'critical', severity: 'critical', cooldown_sec: 300, check_type: '' }
  let channelBusy = false
  let ruleBusy = false

  $: load()

  async function load() {
    err = ''
    try {
      const [ch, rl, fr] = await Promise.all([api.listChannels(), api.listAlertRules(), api.listFiredAlerts(20)])
      channels = ch || []
      rules = rl || []
      fired = fr || []
      // resolve which channels each rule uses
      for (const r of rules) {
        try { r._channels = await api.listRuleChannels(r.id) } catch (_) { r._channels = [] }
      }
      rules = rules
    } catch (e) {
      err = e.message
    }
  }

  async function addChannel() {
    err = ''
    let payload
    if (nc.type === 'telegram') {
      if (!nc.bot_token || !nc.chat_id) { err = 'bot_token and chat_id required'; return }
      payload = { type: 'telegram', name: nc.name || 'telegram', enabled: true, config: { bot_token: nc.bot_token, chat_id: nc.chat_id } }
    } else {
      if (!nc.url) { err = 'webhook url required'; return }
      const config = { url: nc.url }
      if (nc.secret) config.secret = nc.secret
      payload = { type: 'webhook', name: nc.name || 'webhook', enabled: true, config }
    }
    channelBusy = true
    try {
      await api.createChannel(payload)
      nc = { type: nc.type, name: '', bot_token: '', chat_id: '', url: '', secret: '' }
      await load()
    } catch (e) { err = e.message } finally { channelBusy = false }
  }

  async function removeChannel(id) {
    if (!confirm($t('al.confirmDeleteChannel'))) return
    try { await api.deleteChannel(id); await load() } catch (e) { err = e.message }
  }

  async function addRule() {
    if (!nr.name.trim()) { err = 'rule name required'; return }
    ruleBusy = true; err = ''
    try {
      const res = await api.createAlertRule({ name: nr.name, trigger_status: nr.trigger_status, severity: nr.severity, cooldown_sec: Number(nr.cooldown_sec) || 300, check_type: nr.check_type || '' })
      // auto-attach the first channel if any
      if (channels.length) { try { await api.attachChannel(res.id, channels[0].id) } catch (_) {} }
      nr = { name: '', trigger_status: 'critical', severity: 'critical', cooldown_sec: 300, check_type: '' }
      await load()
    } catch (e) { err = e.message } finally { ruleBusy = false }
  }

  async function removeRule(id) {
    if (!confirm('Delete this rule?')) return
    try { await api.deleteAlertRule(id); await load() } catch (e) { err = e.message }
  }

  async function attachFirstChannel(ruleId) {
    if (!channels.length) { err = 'add a channel first'; return }
    try { await api.attachChannel(ruleId, channels[0].id); await load() } catch (e) { err = e.message }
  }
</script>

<div class="h-full overflow-auto p-4 space-y-4 max-w-5xl mx-auto">
  <div class="hud-panel p-4 space-y-3">
    <div class="flex items-center gap-2">
      <h2 class="font-mono text-neon-green text-lg">{$t('al.channels', { n: channels.length })}</h2>
    </div>
    <p class="text-xs text-hud-dim">{$t('al.channelsHint')}</p>

    {#if channels.length}
      <div class="space-y-1">
        {#each channels as c (c.id)}
          <div class="flex items-center gap-2 border border-hud-line rounded px-2 py-1.5 text-xs font-mono">
            <span class="text-neon-cyan uppercase w-20">{c.type}</span>
            <span class="text-emerald-100 flex-1 truncate">{c.name}</span>
            <span class="text-hud-dim truncate max-w-[40%]">{c.config?.chat_id || c.config?.url || ''}</span>
            <button class="hud-btn !py-0.5 !text-neon-red border-neon-red/40" on:click={() => removeChannel(c.id)}>✕</button>
          </div>
        {/each}
      </div>
    {/if}

    <form on:submit|preventDefault={addChannel} class="grid grid-cols-2 gap-2">
      <select class="hud-input col-span-2" bind:value={nc.type}>
        <option value="telegram">telegram</option>
        <option value="webhook">{$t('al.wh')}</option>
      </select>
      <input class="hud-input col-span-2" placeholder={$t('al.namePh')} bind:value={nc.name} />
      {#if nc.type === 'telegram'}
        <input class="hud-input" placeholder="bot_token (from @BotFather)" bind:value={nc.bot_token} />
        <input class="hud-input" placeholder="chat_id" bind:value={nc.chat_id} />
      {:else}
        <input class="hud-input col-span-2" placeholder={$t('al.urlPh')} bind:value={nc.url} />
        <input class="hud-input col-span-2" placeholder={$t('al.secretPh')} bind:value={nc.secret} />
      {/if}
      <button class="hud-btn hud-btn-primary col-span-2" disabled={channelBusy}>{channelBusy ? '…' : $t('al.addChannel', { type: nc.type })}</button>
    </form>
  </div>

  <div class="hud-panel p-4 space-y-3">
    <h2 class="font-mono text-neon-green text-lg">{$t('al.rules', { n: rules.length })}</h2>
    <p class="text-xs text-hud-dim">{$t('al.rulesHint')}</p>

    {#if rules.length}
      <div class="space-y-1">
        {#each rules as r (r.id)}
          <div class="border border-hud-line rounded px-2 py-1.5 text-xs font-mono space-y-1">
            <div class="flex items-center gap-2">
              <span class="text-emerald-100 flex-1 truncate">{r.name}</span>
              <span class="hud-label {r.severity === 'critical' ? 'text-neon-red' : 'text-neon-amber'}">{r.severity}</span>
              <span class="text-hud-dim">on {r.trigger_status}</span>
              <span class="text-hud-dim">cd {r.cooldown_sec}s</span>
              {#if r.check_type}<span class="text-hud-dim">· {r.check_type}</span>{/if}
              <button class="hud-btn !py-0.5 !text-neon-red border-neon-red/40" on:click={() => removeRule(r.id)}>✕</button>
            </div>
            <div class="text-[11px] text-hud-dim">→ {(r._channels || []).map((c) => c.type + ':' + c.name).join(', ') || $t('al.noChannel')}<button class="hud-btn !px-2 !py-0.5 ml-1" on:click={() => attachFirstChannel(r.id)}>{$t('al.attach')}</button></div>
          </div>
        {/each}
      </div>
    {/if}

    <form on:submit|preventDefault={addRule} class="grid grid-cols-2 md:grid-cols-4 gap-2">
      <input class="hud-input col-span-2" placeholder={$t('al.ruleNamePh')} bind:value={nr.name} />
      <select class="hud-input" bind:value={nr.trigger_status}>
        <option value="critical">{$t('al.trigger')}: critical</option>
        <option value="warn">{$t('al.trigger')}: warn</option>
        <option value="unknown">{$t('al.trigger')}: unknown</option>
      </select>
      <select class="hud-input" bind:value={nr.severity}>
        <option value="critical">{$t('al.severity')}: critical</option>
        <option value="warning">{$t('al.severity')}: warning</option>
      </select>
      <select class="hud-input" bind:value={nr.check_type}>
        <option value="">{$t('al.checkType')}: any</option>
        <option value="liveness">{$t('al.checkType')}: liveness</option>
        <option value="tcp">{$t('al.checkType')}: tcp</option>
        <option value="http">{$t('al.checkType')}: http</option>
        <option value="tls">{$t('al.checkType')}: tls</option>
        <option value="dns">{$t('al.checkType')}: dns</option>
        <option value="dnsbl">{$t('al.checkType')}: dnsbl</option>
      </select>
      <input class="hud-input" type="number" placeholder={$t('al.cooldown')} bind:value={nr.cooldown_sec} />
      <button class="hud-btn hud-btn-primary col-span-2 md:col-span-2" disabled={ruleBusy}>{ruleBusy ? '…' : $t('al.addRule')}</button>
    </form>
  </div>

  <div class="hud-panel p-4 space-y-3">
    <h2 class="font-mono text-neon-green text-lg">{$t('al.fired', { n: fired.length })}</h2>
    <p class="text-xs text-hud-dim">{$t('al.firedHint')}</p>
    {#if fired.length}
      <div class="space-y-1 max-h-64 overflow-auto">
        {#each fired as f (f.id)}
          <div class="text-xs font-mono border-l-2 border-neon-amber/40 pl-2">
            <span class="text-hud-dim">{f.triggered_at?.slice(0,19).replace('T',' ')}</span>
            <span class="text-neon-amber ml-1">[{f.severity}]</span>
            <span class="text-emerald-200/80">vm {f.vm_id ?? '—'}</span>
            <span class="text-hud-dim break-all"> {f.message}</span>
          </div>
        {/each}
      </div>
    {:else}
      <div class="hud-label text-hud-dim">{$t('al.noFired')}</div>
    {/if}
  </div>

  {#if err}<div class="text-xs font-mono text-neon-red">{err}</div>{/if}
</div>
