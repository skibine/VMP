/** @type {import('tailwindcss').Config} */
// region tailwind [DOMAIN(6): Design; CONCEPT(7]: HUD; TECH(7]: tailwind]
// HUD palette: near-black canvas, emerald/cyan neon, amber/red/slate health.
export default {
  content: ['./index.html', './src/**/*.{svelte,js}'],
  theme: {
    extend: {
      colors: {
        hud: {
          bg: '#070a08',
          panel: '#0c110d',
          panel2: '#101711',
          line: '#1c2a20',
          dim: '#5b6b5f'
        },
        neon: {
          green: '#34d399',
          cyan: '#22d3ee',
          amber: '#fbbf24',
          red: '#f87171'
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'JetBrains Mono', 'Menlo', 'monospace']
      }
    }
  },
  plugins: []
}
