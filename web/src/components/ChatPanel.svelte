<script>
  import { api } from '../lib/api.js'
  import { t } from '../lib/i18n.js'
  import { onMount, onDestroy, afterUpdate } from 'svelte'
  import ArtifactRenderer from './ArtifactRenderer.svelte'

  // region ChatPanel [DOMAIN(8): AI; CONCEPT(8]: Copilot; TECH(6]: svelte]
  // Always-visible VMPilot AI assistant. Parses ```vmpulse-artifact fenced blocks from replies into
  // a rendered artifact spec (stub renderer this slice).
  let input = ''
  let busy = false
  let messages = [] // {role, text, artifact, trace}

  // Stick-to-bottom autoscroll. `stick` tracks whether the user is parked at the bottom, set by the
  // scroll EVENT (user-driven), NOT re-measured after content grows. Measuring nearBottom AFTER a
  // large reply / approval block lands makes it falsely false (scrollHeight already grew) and skips
  // the scroll — the classic autoscroll bug. So we remember "was the user at the bottom?" and
  // re-apply scrollTop=scrollHeight on every update while stick is true. Scrolling up clears stick,
  // so reading history is never interrupted.
  //
  // forceScroll: an active conversation turn (the user's own message, or the assistant's reply they
  // are waiting for) must ALWAYS scroll into view — even if the user scrolled up during a long
  // (local-LLM) wait. Without this, a reply that arrives after a slow Ollama turn lands below the
  // fold and looks like "no answer" until a tab switch remounts.
  let scroller = null
  let stick = true
  let forceScroll = false
  function onScrollerScroll() {
    if (!scroller) return
    stick = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 120
  }
  afterUpdate(() => {
    if (!scroller) return
    if (forceScroll || stick) scroller.scrollTop = scroller.scrollHeight
    forceScroll = false
  })

  // Server-side SHARED history (migration 0027): the same conversation the Telegram bridge uses,
  // so a thread started here continues in Telegram and vice versa. The old localStorage cache is
  // dead — on mount the transcript is loaded from /api/ai/history.
  async function loadHistory() {
    try {
      const res = await api.aiHistory()
      messages = (res.messages || []).map((m) => ({ role: m.role, text: m.content }))
    } catch (_) { /* keep whatever is on screen */ }
  }

  function clearChat() {
    messages = []
    api.clearAIHistory().catch(() => {})
  }

  // Pending AI actions (Plane B approval). Polled so an out-of-band proposal surfaces here.
  let pending = []
  let actionBusy = {} // id -> true while approving/rejecting
  let pollTimer = null

  onMount(() => {
    loadHistory()
    refreshPending()
    pollTimer = setInterval(refreshPending, 2000)
  })
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer) })

  async function refreshPending() {
    try {
      const res = await api.listAIActions('pending')
      pending = res.actions || []
    } catch (_) { /* ignore — chat still works */ }
  }

  // ```vmpulse-artifact\n{...json...}```  -> {text, artifact}
  function parseReply(reply) {
    const re = /```vmpulse-artifact\s*\n([\s\S]*?)```/i
    const m = reply.match(re)
    if (!m) return { text: reply, artifact: null }
    let spec = null
    try {
      spec = JSON.parse(m[1].trim())
    } catch (_) {
      spec = { type: 'invalid', raw: m[1] }
    }
    return { text: reply.replace(re, '').trim(), artifact: spec }
  }

  async function send() {
    const text = input.trim()
    if (!text || busy) return
    input = ''
    await askAI(text, { role: 'user', text })
  }

  // askAI sends one turn to the assistant. `userMsg` is pushed to the transcript first (the user's
  // text, or a synthetic system-injected note). Used by send() and by the post-approve continuation.
  // History lives SERVER-side (shared with Telegram): the request carries no history.
  async function askAI(text, userMsg) {
    messages = [...messages, userMsg]
    forceScroll = true
    busy = true
    try {
      const res = await api.aiChat(text, [])
      const parsed = parseReply(res.reply || '')
      messages = [...messages, { role: 'assistant', text: parsed.text, artifact: parsed.artifact, trace: res.trace || [] }]
      forceScroll = true
    } catch (e) {
      messages = [...messages, { role: 'assistant', text: '⚠ ' + e.message, artifact: null, trace: [] }]
    } finally {
      busy = false
    }
  }

  async function approve(a) {
    actionBusy = { ...actionBusy, [a.id]: true }
    let res
    try {
      res = await api.approveAIAction(a.id)
      a._result = res
      a._done = true
    } catch (e) {
      a._result = { status: 'error', error: e.message }
      a._done = true
    } finally {
      actionBusy = { ...actionBusy, [a.id]: false }
      setTimeout(refreshPending, 500)
    }
    // Close the loop: feed the execution result back to the assistant so it reports automatically
    // (no need for the user to ask "what happened?").
    if (res) {
      const vm = pending.find((p) => p.id === a.id) || a
      const note = `[action executed] action #${a.id} "${a.command}" on VM ${a.vm_id} was approved and run.\nstatus: ${res.status}\noutput:\n${res.output || '(none)'}\n${res.error ? 'error: ' + res.error : ''}\nReport the result to the user concisely.`
      await askAI(note, { role: 'user', text: note, synthetic: true })
    }
  }

  async function reject(a) {
    actionBusy = { ...actionBusy, [a.id]: true }
    try { await api.rejectAIAction(a.id); pending = pending.filter((x) => x.id !== a.id) }
    catch (_) {} finally { actionBusy = { ...actionBusy, [a.id]: false } }
  }

  function onKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }
</script>

<div class="flex flex-col h-full">
  <div class="px-3 py-2 border-b border-hud-line flex items-center gap-2">
    <span class="relative flex h-2 w-2">
      <span class="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 bg-neon-cyan"></span>
      <span class="relative inline-flex rounded-full h-2 w-2 bg-neon-cyan"></span>
    </span>
    <span class="hud-label text-neon-cyan">vmpilot</span>
    <span class="hud-label text-hud-dim ml-2">{$t('chat.ctx')}</span>
    {#if messages.length}
      <button class="hud-btn !py-0.5 !text-xs ml-auto" on:click={clearChat} title="clear chat">{$t('chat.clear')}</button>
    {/if}
  </div>

  <div bind:this={scroller} on:scroll={onScrollerScroll} class="flex-1 overflow-auto p-3 space-y-3">
    {#if !messages.length}
      <div class="hud-panel p-3 text-xs text-hud-dim space-y-2">
        <div class="hud-label">{$t('chat.hints')}</div>
        <p>· "какие у меня ВМ и их здоровье?"</p>
        <p>· "покажи последние алерты"</p>
        <p>· "проверь состояние vm 1"</p>
      </div>
    {/if}
    {#each messages as m}
      <div class="space-y-1">
        <div class="hud-label">{m.synthetic ? $t('chat.actionResult') : m.role === 'user' ? $t('chat.you') : '< vmpilot'}</div>
        {#if m.text}
          <div
            class="text-sm whitespace-pre-wrap {m.synthetic
              ? 'text-hud-dim italic border-l-2 border-hud-line pl-2'
              : m.role === 'user'
                ? 'text-emerald-100'
                : 'text-neon-green/90'}"
          >
            {m.text}
          </div>
        {/if}
        {#if m.artifact}
          <ArtifactRenderer spec={m.artifact} />
        {/if}
        {#if m.trace?.length}
          <details class="text-[11px] font-mono border border-hud-line rounded mt-1">
            <summary class="hud-label text-hud-dim cursor-pointer px-2 py-0.5">{$t('chat.activity', { n: m.trace.length })}</summary>
            <div class="px-2 py-1 space-y-0.5">
              {#each m.trace as t}
                <div class="text-hud-dim"><span class="text-neon-cyan">▸ {t.tool}</span> <span class="text-emerald-200/60 break-all">{t.args}</span> <span class="text-hud-dim">→ {t.result}</span></div>
              {/each}
            </div>
          </details>
        {/if}
      </div>
    {/each}
    {#if busy}
      <div class="hud-label text-neon-cyan"><span class="hud-spinner"></span> {$t('chat.thinking')}</div>
    {/if}
    {#if pending.length}
      <div class="space-y-2 pt-2">
        <div class="hud-label text-neon-amber">{$t('chat.pending', { n: pending.length })}</div>
        {#each pending as a (a.id)}
          <div class="hud-panel p-2 space-y-1 border-neon-amber/40">
            <div class="text-xs font-mono break-all"><span class="hud-label text-hud-dim">{$t('chat.vm', { id: a.vm_id })}</span> <span class="text-emerald-200/90">{a.command}</span></div>
            {#if a.reason}<div class="text-[11px] font-mono text-hud-dim">{$t('chat.why')} {a.reason}</div>{/if}
            {#if a._done && a._result}
              <div class="text-[11px] font-mono whitespace-pre-wrap {a._result.status === 'done' ? 'text-neon-green' : 'text-neon-red'}">{a._result.status === 'done' ? '✓ ' : '✗ '}{a._result.output || a._result.error || ''}</div>
            {:else}
              <div class="flex items-center gap-2">
                <button class="hud-btn hud-btn-primary !py-0.5 !text-xs" on:click={() => approve(a)} disabled={actionBusy[a.id]}>{actionBusy[a.id] ? '…' : $t('chat.approve')}</button>
                <button class="hud-btn !py-0.5 !text-xs" on:click={() => reject(a)} disabled={actionBusy[a.id]}>{$t('chat.reject')}</button>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <div class="p-3 border-t border-hud-line">
    <textarea
      class="hud-input resize-none"
      rows="2"
      placeholder={$t('chat.placeholder')}
      bind:value={input}
      on:keydown={onKey}
    ></textarea>
  </div>
</div>
