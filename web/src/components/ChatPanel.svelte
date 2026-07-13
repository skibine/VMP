<script>
  import { api } from '../lib/api.js'
  import { onMount, onDestroy } from 'svelte'
  import ArtifactRenderer from './ArtifactRenderer.svelte'

  // region ChatPanel [DOMAIN(8): AI; CONCEPT(8]: Copilot; TECH(6]: svelte]
  // Always-visible VMPilot AI assistant. Parses ```vmpulse-artifact fenced blocks from replies into
  // a rendered artifact spec (stub renderer this slice).
  let input = ''
  let busy = false
  let messages = [] // {role, text, artifact, trace}

  // Persist chat to localStorage so it survives reloads (history is in-memory on the server side too).
  const STORE_KEY = 'vmp_chat'
  function persist() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(messages.slice(-100))) } catch (_) {}
  }
  function restore() {
    try {
      const raw = localStorage.getItem(STORE_KEY)
      if (raw) messages = JSON.parse(raw)
    } catch (_) {}
  }
  restore()

  function clearChat() {
    messages = []
    persist()
  }

  // Pending AI actions (Plane B approval). Polled so an out-of-band proposal surfaces here.
  let pending = []
  let actionBusy = {} // id -> true while approving/rejecting
  let pollTimer = null

  onMount(() => { refreshPending(); pollTimer = setInterval(refreshPending, 4000) })
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
    messages = [...messages, { role: 'user', text }]
    persist()
    busy = true
    try {
      // Only the last 8 user/assistant turns are sent as LLM context (provider window constraint).
      const history = messages
        .filter((m) => m.role === 'user' || m.role === 'assistant')
        .slice(-9, -1)
        .map((m) => ({ role: m.role, content: m.text }))
      const res = await api.aiChat(text, history)
      const parsed = parseReply(res.reply || '')
      messages = [...messages, { role: 'assistant', text: parsed.text, artifact: parsed.artifact, trace: res.trace || [] }]
      persist()
    } catch (e) {
      messages = [...messages, { role: 'assistant', text: '⚠ ' + e.message, artifact: null, trace: [] }]
      persist()
    } finally {
      busy = false
    }
  }

  async function approve(a) {
    actionBusy = { ...actionBusy, [a.id]: true }
    try {
      const res = await api.approveAIAction(a.id)
      a._result = res
      a._done = true
    } catch (e) { a._result = { status: 'error', error: e.message }; a._done = true }
    finally { actionBusy = { ...actionBusy, [a.id]: false }; setTimeout(refreshPending, 500) }
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
    <span class="hud-label text-hud-dim ml-2">ctx: last 8 turns</span>
    {#if messages.length}
      <button class="hud-btn !py-0.5 !text-xs ml-auto" on:click={clearChat} title="clear chat">clear</button>
    {/if}
  </div>

  <div class="flex-1 overflow-auto p-3 space-y-3">
    {#if !messages.length}
      <div class="hud-panel p-3 text-xs text-hud-dim space-y-2">
        <div class="hud-label">// hints</div>
        <p>· "какие у меня ВМ и их здоровье?"</p>
        <p>· "покажи последние алерты"</p>
        <p>· "проверь состояние vm 1"</p>
      </div>
    {/if}
    {#each messages as m}
      <div class="space-y-1">
        <div class="hud-label">{m.role === 'user' ? '> you' : '< vmpilot'}</div>
        {#if m.text}
          <div
            class="text-sm whitespace-pre-wrap {m.role === 'user'
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
            <summary class="hud-label text-hud-dim cursor-pointer px-2 py-0.5">activity ({m.trace.length})</summary>
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
      <div class="hud-label animate-pulse">vmpilot thinking…</div>
    {/if}
    {#if pending.length}
      <div class="space-y-2 pt-2">
        <div class="hud-label text-neon-amber">// pending actions ({pending.length}) — approve to execute</div>
        {#each pending as a (a.id)}
          <div class="hud-panel p-2 space-y-1 border-neon-amber/40">
            <div class="text-xs font-mono break-all"><span class="hud-label text-hud-dim">vm {a.vm_id}:</span> <span class="text-emerald-200/90">{a.command}</span></div>
            {#if a.reason}<div class="text-[11px] font-mono text-hud-dim">why: {a.reason}</div>{/if}
            {#if a._done && a._result}
              <div class="text-[11px] font-mono whitespace-pre-wrap {a._result.status === 'done' ? 'text-neon-green' : 'text-neon-red'}">{a._result.status === 'done' ? '✓ ' : '✗ '}{a._result.output || a._result.error || ''}</div>
            {:else}
              <div class="flex items-center gap-2">
                <button class="hud-btn hud-btn-primary !py-0.5 !text-xs" on:click={() => approve(a)} disabled={actionBusy[a.id]}>{actionBusy[a.id] ? '…' : '✓ approve'}</button>
                <button class="hud-btn !py-0.5 !text-xs" on:click={() => reject(a)} disabled={actionBusy[a.id]}>✕ reject</button>
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
      placeholder="ask vmpilot… (enter to send)"
      bind:value={input}
      on:keydown={onKey}
    ></textarea>
  </div>
</div>
