/** @type {import('tailwindcss').Config} */
// region tailwind [DOMAIN(6): Design; CONCEPT(7]: Theming; TECH(7]: tailwind,css-vars]
// HUD palette is CSS-variable-backed (space-separated RGB channels) so a `.light` class on
// <html> can swap the whole theme with ZERO component changes. Opacity modifiers (/40, /80, ...)
// keep working via the <alpha-value> placeholder. Channels are defined in app.css (:root = dark,
// .light = light). emerald-100/200 are also themed (used for value text across components).
export default {
  content: ['./index.html', './src/**/*.{svelte,js}'],
  theme: {
    extend: {
      colors: {
        hud: {
          bg: 'rgb(var(--hud-bg) / <alpha-value>)',
          panel: 'rgb(var(--hud-panel) / <alpha-value>)',
          panel2: 'rgb(var(--hud-panel2) / <alpha-value>)',
          line: 'rgb(var(--hud-line) / <alpha-value>)',
          dim: 'rgb(var(--hud-dim) / <alpha-value>)'
        },
        neon: {
          green: 'rgb(var(--neon-green) / <alpha-value>)',
          cyan: 'rgb(var(--neon-cyan) / <alpha-value>)',
          amber: 'rgb(var(--neon-amber) / <alpha-value>)',
          red: 'rgb(var(--neon-red) / <alpha-value>)'
        },
        // Override only the two emerald shades used for value text so they theme too.
        emerald: {
          100: 'rgb(var(--emerald-100) / <alpha-value>)',
          200: 'rgb(var(--emerald-200) / <alpha-value>)'
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'JetBrains Mono', 'Menlo', 'monospace']
      }
    }
  },
  plugins: []
}
