<script>
  // region HealthBadge [DOMAIN(7): UI; CONCEPT(6]: Health; TECH(5]: svelte]
  // Colored status dot + score from the K2 health-score.
  export let status = 'unknown'
  export let score = null

  $: color =
    status === 'ok'
      ? 'neon-green'
      : status === 'warn'
        ? 'neon-amber'
        : status === 'critical'
          ? 'neon-red'
          : 'hud-dim'
</script>

<div class="flex items-center gap-2">
  <span class="relative flex h-2.5 w-2.5">
    <span
      class="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 bg-{color}"
    ></span>
    <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-{color}"></span>
  </span>
  <span class="hud-label text-{color}">{status}</span>
  {#if score !== null && score !== undefined}
    <span class="ml-auto font-mono text-sm text-{color} tabular-nums">{score}</span>
  {/if}
</div>
