<script>
  // region Terminal [DOMAIN(9): Security; CONCEPT(8): WebSSH; TECH(7): Svelte,xterm,websocket]
  // @purpose Interactive SSH terminal mounted in the VM detail. xterm.js over a WebSocket that the
  // backend bridges to a remote PTY. Dispatches 'error' with a server reason (no creds / host key).
  import { onMount, onDestroy, createEventDispatcher } from 'svelte'
  import { Terminal } from '@xterm/xterm'
  import { FitAddon } from '@xterm/addon-fit'
  import '@xterm/xterm/css/xterm.css'
  import { terminalUrl } from '../lib/api.js'
  import { t } from '../lib/i18n.js'

  export let vmId
  const dispatch = createEventDispatcher()
  let el
  let term, fit, ws, ro
  let status = 'connecting'

  onMount(() => {
    term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      theme: { background: '#0a0e14', foreground: '#cdd6f4', cursor: '#cdd6f4', selectionBackground: '#334155' }
    })
    fit = new FitAddon()
    term.loadAddon(fit)
    term.open(el)
    try { fit.fit() } catch (_) { /* not laid out yet */ }
    openWS()
    ro = new ResizeObserver(() => { try { fit.fit() } catch (_) {} })
    ro.observe(el)
  })

  function openWS() {
    ws = new WebSocket(terminalUrl(vmId))
    ws.binaryType = 'arraybuffer'
    ws.onopen = () => {
      status = 'live'
      sendResize()
    }
    ws.onmessage = (e) => {
      // Text frames are server control/error JSON (sent before a close). Binary = PTY output.
      if (typeof e.data === 'string') {
        try {
          const m = JSON.parse(e.data)
          if (m.error) {
            status = 'error'
            dispatch('error', m)
          }
        } catch (_) {
          /* ignore non-JSON text */
        }
        return
      }
      term.write(new Uint8Array(e.data))
    }
    ws.onclose = () => {
      if (status !== 'error') status = 'closed'
      dispatch('closed')
    }
    ws.onerror = () => {
      status = 'error'
    }
    term.onData((d) => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d))
    })
    term.onResize(() => sendResize())
  }

  function sendResize() {
    if (ws && ws.readyState === WebSocket.OPEN && term) {
      ws.send(JSON.stringify({ t: 'resize', cols: term.cols, rows: term.rows }))
    }
  }

  onDestroy(() => {
    if (ws) ws.close()
    if (term) term.dispose()
    if (ro) ro.disconnect()
  })
</script>

<div class="terminal-wrap">
  <div class="tbar"><span class="dot {status}"></span> {$t('term.title', { status: $t('term.' + status) })}</div>
  <div class="term" bind:this={el}></div>
</div>

<style>
  .terminal-wrap {
    border: 1px solid #1f2937;
    background: #0a0e14;
    border-radius: 4px;
  }
  .tbar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    font-size: 11px;
    letter-spacing: 0.04em;
    color: #94a3b8;
    border-bottom: 1px solid #1f2937;
    text-transform: uppercase;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6b7280;
  }
  .dot.live { background: #22c55e; }
  .dot.connecting { background: #eab308; }
  .dot.closed { background: #6b7280; }
  .dot.error { background: #ef4444; }
  .term {
    height: 360px;
    padding: 6px;
  }
</style>
