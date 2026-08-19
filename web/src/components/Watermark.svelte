<script>
  // region Watermark [DOMAIN(6): UI; CONCEPT(6): Branding; TECH(5): svelte]
  // Big faint product logo pinned to the viewport bottom-right, present on every view.
  // Layering contract (see Dashboard): watermark is position:fixed with z-0; every content
  // <main> in Dashboard carries relative z-10, so the logo sits ABOVE the hud-grid pattern
  // (which is a mere semi-transparent background-image on the sections) and BELOW every
  // panel/card. pointer-events-none keeps it decorative only.
</script>

<img
  src="/logo.png"
  alt=""
  aria-hidden="true"
  class="pointer-events-none select-none fixed z-0 right-6 bottom-6 w-[440px] max-w-[46vw] opacity-[0.35]"
  draggable="false"
/>
