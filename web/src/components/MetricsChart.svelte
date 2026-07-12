<script>
  // region MetricsChart [DOMAIN(8): Observability; CONCEPT(7]: Sparkline; TECH(6]: SVG,svelte]
  // Single-metric SVG sparkline + current value. No chart library (keeps bundle small next to xterm).
  // region
  export let label = ''
  export let unit = ''
  export let data = [] // array of [ts, value]
  export let color = '#22d3ee' // neon-cyan default
  export let decimals = 0

  $: arr = Array.isArray(data) ? data : []
  $: n = arr.length
  $: cur = n ? Number(arr[n - 1][1]) : null
  $: pts = buildPath(arr)

  const W = 150
  const H = 30

  function buildPath(d) {
    if (!d || d.length < 2) return ''
    let min = Infinity
    let max = -Infinity
    for (const [, v] of d) {
      if (v < min) min = v
      if (v > max) max = v
    }
    if (max - min < 1e-9) max = min + 1 // avoid divide-by-zero for flat series
    const stepX = W / (d.length - 1)
    let path = ''
    for (let i = 0; i < d.length; i++) {
      const x = i * stepX
      const y = H - ((d[i][1] - min) / (max - min)) * (H - 2) - 1
      path += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1) + ' '
    }
    return path.trim()
  }

  function fmt(v) {
    if (v === null || v === undefined) return '—'
    return Number(v).toFixed(decimals)
  }
</script>

<div class="spark">
  <div class="head">
    <span class="lab">{label}</span>
    <span class="val" style="color:{color}">{fmt(cur)}<span class="unit">{unit}</span></span>
  </div>
  <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" class="svg">
    {#if pts}
      <path d={pts} fill="none" stroke={color} stroke-width="1.4" stroke-linejoin="round" />
    {:else}
      <text x="2" y="18" class="empty">// no data</text>
    {/if}
  </svg>
</div>

<style>
  .spark {
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 6px 8px;
    background: #0d1117;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 2px;
  }
  .lab {
    font-size: 10px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #94a3b8;
  }
  .val {
    font-family: ui-monospace, monospace;
    font-size: 14px;
    font-weight: 600;
  }
  .unit {
    font-size: 10px;
    color: #6b7280;
    margin-left: 2px;
  }
  .svg {
    width: 100%;
    height: 30px;
    display: block;
  }
  .empty {
    fill: #475569;
    font-size: 9px;
    font-family: ui-monospace, monospace;
  }
</style>
