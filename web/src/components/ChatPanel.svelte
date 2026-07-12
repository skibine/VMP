<script>
  import { api } from '../lib/api.js'
  import ArtifactRenderer from './ArtifactRenderer.svelte'

  // region ChatPanel [DOMAIN(8): AI; CONCEPT(8]: Copilot; TECH(6]: svelte]
  // Always-visible AI copilot. Parses ```vmpulse-artifact fenced blocks from replies into
  // a rendered artifact spec (stub renderer this slice).
  let input = ''
  let busy = false
  let messages = [] // {role, text, artifact}

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
    busy = true
    try {
      const history = messages
        .filter((m) => m.role === 'user' || m.role === 'assistant')
        .slice(-8)
        .map((m) => ({ role: m.role, content: m.text }))
      const res = await api.aiChat(text, history)
      const parsed = parseReply(res.reply || '')
      messages = [...messages, { role: 'assistant', text: parsed.text, artifact: parsed.artifact }]
    } catch (e) {
      messages = [...messages, { role: 'assistant', text: '⚠ ' + e.message, artifact: null }]
    } finally {
      busy = false
    }
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
    <span class="hud-label text-neon-cyan">copilot</span>
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
        <div class="hud-label">{m.role === 'user' ? '> you' : '< copilot'}</div>
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
      </div>
    {/each}
    {#if busy}
      <div class="hud-label animate-pulse">copilot thinking…</div>
    {/if}
  </div>

  <div class="p-3 border-t border-hud-line">
    <textarea
      class="hud-input resize-none"
      rows="2"
      placeholder="ask the copilot… (enter to send)"
      bind:value={input}
      on:keydown={onKey}
    ></textarea>
  </div>
</div>
