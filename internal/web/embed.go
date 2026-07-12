// Package web embeds the built SPA (internal/web/dist) so the single Go binary serves it.
//
// region MODULE_CONTRACT [DOMAIN(7): UI; CONCEPT(7]: Embed; TECH(8]: go:embed]
// @purpose Expose the compiled frontend as an embed.FS for the API server to serve. The dist
//
//	directory is a build artifact (run `npm run build` in web/ before `go build`).
//
// @invariants
//   - Dist always contains at least index.html after a successful frontend build.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: embed, dist, SPA, frontend, static, go:embed
// STRUCTURE: ▶ ┌dist/┐ → ⚡ go:embed all → ⊕ Dist embed.FS → ⎷ api serve
package web

import "embed"

// Dist holds the compiled SPA assets.
//
//go:embed all:dist
var Dist embed.FS
