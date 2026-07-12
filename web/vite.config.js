import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// region vite [DOMAIN(7): Build; CONCEPT(7]: Frontend; TECH(8]: vite]
// Build the HUD SPA into ../internal/web/dist so the Go binary can embed it (single binary).
// Dev server proxies /api + /healthz to the Go backend on :8443.
export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8443',
      '/healthz': 'http://127.0.0.1:8443'
    }
  },
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true
  }
})
