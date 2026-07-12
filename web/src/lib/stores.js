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
