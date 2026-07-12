import { token, logout } from './stores.js'

// region api [DOMAIN(7): Client; CONCEPT(8]: REST; TECH(7]: fetch]
// Thin fetch wrapper. Attaches the bearer token from the session store; on 401 logs out.
async function req(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  if (auth) {
    let t
    const unsub = token.subscribe((v) => (t = v))
    unsub()
    if (t) headers.Authorization = 'Bearer ' + t
  }
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined })
  if (res.status === 401 && auth) {
    logout()
    throw new Error('unauthorized')
  }
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch (_) {
    /* non-JSON body */
  }
  if (!res.ok) throw new Error((data && data.error) || res.statusText || 'request failed')
  return data
}

export const api = {
  login: (username, password) =>
    req('/api/auth/login', { method: 'POST', body: { username, password }, auth: false }),
  logout: () => req('/api/auth/logout', { method: 'POST' }).catch(() => {}),
  me: () => req('/api/auth/me'),
  listVms: () => req('/api/vms'),
  createVm: (vm) => req('/api/vms', { method: 'POST', body: vm }),
  vmHealth: (id) => req('/api/vms/' + id + '/health'),
  aiChat: (message, history) => req('/api/ai/chat', { method: 'POST', body: { message, history } })
}
