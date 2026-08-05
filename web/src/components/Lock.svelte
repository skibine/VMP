<script>
  // region Lock [DOMAIN(6): UI; CONCEPT(6): Icon; TECH(5): svelte,svg]
  // Monochrome HUD padlock (fill = currentColor). Shown on a server card/sidebar/detail when SSH
  // credentials are stored in the vault — a visual cue for the "creds ⇔ 2FA" invariant.
  export let size = 12
  export let cls = ''
</script>

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width={size} height={size} class={cls} aria-hidden="true">
  <path fill-rule="evenodd" clip-rule="evenodd" d="M6 9a6 6 0 1 1 12 0v2h.5a2.5 2.5 0 0 1 2.5 2.5v6A2.5 2.5 0 0 1 18.5 22h-13A2.5 2.5 0 0 1 3 19.5v-6A2.5 2.5 0 0 1 5.5 11H6V9Zm9 2V9a3 3 0 1 0-6 0v2h6Zm-3 4a1.5 1.5 0 0 0-1 2.6V18a1 1 0 1 0 2 0v-.4a1.5 1.5 0 0 0-1-2.6Z" />
</svg>
