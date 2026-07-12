<script>
  // region ArtifactRenderer [DOMAIN(8): AI; CONCEPT(7]: Artifact; TECH(5]: svelte]
  // Renders a parsed AI artifact spec. v0 = stub; the chart component arrives next slice.
  export let spec = null
  $: kind = spec?.type || 'unknown'
</script>

{#if spec}
  <div class="hud-panel border-neon-cyan/30 p-3 space-y-1">
    <div class="hud-label text-neon-cyan">artifact&nbsp;//&nbsp;{kind}</div>
    <pre class="text-[11px] text-hud-dim font-mono overflow-auto max-h-40">{JSON.stringify(spec, null, 2)}</pre>
    <div class="text-[10px] text-hud-dim font-mono">// chart renderer: next slice</div>
  </div>
{/if}
