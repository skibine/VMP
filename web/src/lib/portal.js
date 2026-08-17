// region portal [DOMAIN(7): UI; CONCEPT(8): EscapeStackingContext; TECH(6): svelte action]
// Svelte action: relocate the node to <body> on mount. Needed for position:fixed overlays that
// are RENDERED inside .hud-panel ancestors — backdrop-filter there creates a containing block,
// so `fixed inset-0` would size to the ~40px header instead of the viewport (the "only an edge
// visible" bug). Body has no filtered ancestors, so fixed works as intended after the move.
export function portal(node) {
  document.body.appendChild(node)
  return { destroy() { node.remove() } }
}
