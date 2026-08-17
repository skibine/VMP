import { writable } from 'svelte/store'

// region stores [DOMAIN(7): State; CONCEPT(7]: Session; TECH(6]: svelte/store]
// Auth session persists in localStorage; cleared on logout.
const TOKEN_KEY = 'vmpulse_token'
const USER_KEY = 'vmpulse_user'

export const token = writable(localStorage.getItem(TOKEN_KEY) || '')
export const user = writable(JSON.parse(localStorage.getItem(USER_KEY) || 'null'))

token.subscribe((v) => (v ? localStorage.setItem(TOKEN_KEY, v) : localStorage.removeItem(TOKEN_KEY)))
user.subscribe((v) =>
  v ? localStorage.setItem(USER_KEY, JSON.stringify(v)) : localStorage.removeItem(USER_KEY)
)

export function logout() {
  token.set('')
  user.set(null)
}

// region theme [DOMAIN(6): Design; CONCEPT(7]: Theme; TECH(6]: svelte/store]
// Light/dark theme persists in localStorage and is mirrored to <html class="light">. main.js
// applies the saved class BEFORE mount (no flash); this store drives reactive UI (toggle icon).
const THEME_KEY = 'vmpulse_theme'

function initialTheme() {
  return localStorage.getItem(THEME_KEY) === 'light'
}

function applyTheme(light) {
  document.documentElement.classList.toggle('light', light)
}

export const themeLight = writable(initialTheme())
applyTheme(initialTheme())
themeLight.subscribe((light) => {
  applyTheme(light)
  localStorage.setItem(THEME_KEY, light ? 'light' : 'dark')
})

export function toggleTheme() {
  themeLight.update((v) => !v)
}

// region alerts [DOMAIN(7): State; CONCEPT(7]: AlertRevision; TECH(6]: svelte/store]
// A monotonically increasing counter bumped whenever alert rules/mutes change (fleet toggle, per-VM
// toggle, mute/unmute). Sidebar + fleet subscribe to it so their bells reflect changes made
// anywhere in the app without a manual reload.
export const alertRevision = writable(0)
export function bumpAlerts() {
  alertRevision.update((n) => n + 1)
}

// One-shot signal: a deep component (e.g. VmDetail "go to settings" link) requests the Dashboard
// switch to the Settings view. Dashboard subscribes and resets the flag after switching.
export const gotoSettings = writable(false)

// Bumped whenever a server's SSH credentials are saved/cleared, so the sidebar + fleet matrix
// re-fetch the VM list and update the lock badges without a manual page refresh.
export const credRevision = writable(0)
export function bumpCreds() {
  credRevision.update((n) => n + 1)
}

// Build version stamp (fetched from /api/version on load). Shown in the header so the operator can
// compare their build against a reference (sandbox vs PC) — catches stale/cached bundles.
export const appVersion = writable('')
