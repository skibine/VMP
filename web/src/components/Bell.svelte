<script>
  // region Bell [DOMAIN(6): UI; CONCEPT(6): Icon; TECH(5): svelte,svg]
  // Monochrome HUD bell (fill = currentColor) so callers theme it: dim-green off, bright-green on.
  // Replaces the golden 🔔 emoji which ignored the HUD palette.
  export let size = 14
  export let cls = ''
</script>

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width={size} height={size} class={cls} aria-hidden="true">
  <path fill-rule="evenodd" clip-rule="evenodd" d="M5.25 9a6.75 6.75 0 0 1 13.5 0v.75c0 2.123.8 4.057 2.118 5.52a.75.75 0 0 1-.297 1.206c-1.544.57-3.16.99-4.821 1.243a3.75 3.75 0 0 1-7.5 0c-1.66-.253-3.277-.672-4.821-1.243a.75.75 0 0 1-.297-1.206A8.217 8.217 0 0 0 5.25 9.75V9Zm4.502 8.9a2.25 2.25 0 1 0 4.496 0 25.057 25.057 0 0 1-4.496 0Z" />
</svg>
