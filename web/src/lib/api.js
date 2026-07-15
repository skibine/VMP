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
  loginTwoFA: (pendingToken, code) =>
    req('/api/auth/login/2fa', { method: 'POST', body: { pending_token: pendingToken, code }, auth: false }),
  logout: () => req('/api/auth/logout', { method: 'POST' }).catch(() => {}),
  me: () => req('/api/auth/me'),
  twoFAStatus: () => req('/api/auth/2fa/status'),
  twoFASetup: () => req('/api/auth/2fa/setup', { method: 'POST' }),
  twoFAEnable: (code) => req('/api/auth/2fa/enable', { method: 'POST', body: { code } }),
  twoFADisable: (password) => req('/api/auth/2fa/disable', { method: 'POST', body: { password } }),
  listVms: () => req('/api/vms'),
  getVm: (id) => req('/api/vms/' + id),
  createVm: (vm) => req('/api/vms', { method: 'POST', body: vm }),
  updateVm: (id, vm) => req('/api/vms/' + id, { method: 'PUT', body: vm }),
  archiveVm: (id) => req('/api/vms/' + id + '/archive', { method: 'POST' }),
  deleteVm: (id) => req('/api/vms/' + id, { method: 'DELETE' }),
  listChecks: (vmId) => req('/api/checks?vm_id=' + vmId),
  createCheck: (c) => req('/api/checks', { method: 'POST', body: c }),
  runCheckNow: (id) => req('/api/checks/' + id + '/run', { method: 'POST' }),
  deleteCheck: (id) => req('/api/checks/' + id, { method: 'DELETE' }),
  diagnose: (id, payload) => req('/api/vms/' + id + '/diagnose', { method: 'POST', body: payload }),
  battery: (id) => req('/api/vms/' + id + '/battery'),
  portScan: (id) => req('/api/vms/' + id + '/portscan'),
  ipInfo: (id) => req('/api/vms/' + id + '/ipinfo'),
  vmErrors: (id, range) => req('/api/vms/' + id + '/errors?range=' + (range || '24h')),
  vmUpdates: (id) => req('/api/vms/' + id + '/updates'),
  vmVHosts: (id) => req('/api/vms/' + id + '/vhosts'),
  vmInventory: (id) => req('/api/vms/' + id + '/inventory'),
  refreshInventory: (id) => req('/api/vms/' + id + '/inventory/refresh', { method: 'POST' }),
  listAIActions: (status) => req('/api/ai/actions' + (status ? '?status=' + status : '')),
  approveAIAction: (id) => req('/api/ai/actions/' + id + '/approve', { method: 'POST' }),
  rejectAIAction: (id) => req('/api/ai/actions/' + id + '/reject', { method: 'POST' }),
  siteInfo: (id, url) => req('/api/vms/' + id + '/siteinfo' + (url ? '?url=' + encodeURIComponent(url) : '')),
  listDomains: () => req('/api/domains'),
  createDomain: (d) => req('/api/domains', { method: 'POST', body: d }),
  deleteDomain: (id) => req('/api/domains/' + id, { method: 'DELETE' }),
  domainInfo: (id) => req('/api/domains/' + id + '/info'),
  setAIAccess: (id, enabled) => req('/api/vms/' + id + '/ai-access', { method: 'PUT', body: { enabled } }),
  vmHealth: (id) => req('/api/vms/' + id + '/health'),
  vmResults: (id) => req('/api/vms/' + id + '/results'),
  aiChat: (message, history) => req('/api/ai/chat', { method: 'POST', body: { message, history } }),

  // Settings
  getAISettings: () => req('/api/settings/ai'),
  updateAISettings: (cfg) => req('/api/settings/ai', { method: 'PUT', body: cfg }),
  getVMCreds: (id) => req('/api/vms/' + id + '/credentials'),
  setVMCreds: (id, creds) => req('/api/vms/' + id + '/credentials', { method: 'PUT', body: creds }),
  deleteVMCreds: (id) => req('/api/vms/' + id + '/credentials', { method: 'DELETE' }),

  // Plane B: web-ssh snapshot + TOFU host-key reset.
  snapshot: (id) => req('/api/vms/' + id + '/snapshot', { method: 'POST' }),
  resetHostKey: (id) => req('/api/vms/' + id + '/hostkey', { method: 'DELETE' }),

  // Plane A: metrics time-series + pull-poller toggle.
  metrics: (id, range) => req('/api/vms/' + id + '/metrics' + (range ? '?range=' + range : '')),
  setMetrics: (id, enabled) => req('/api/vms/' + id + '/metrics', { method: 'PUT', body: { enabled } })
}

// terminalUrl builds the WebSocket URL for an interactive web-ssh session. The session token is
// passed via ?token= (browsers cannot set Authorization headers on WS handshakes); it is validated
// server-side and same-origin only.
export function terminalUrl(vmId) {
  let t
  const unsub = token.subscribe((v) => (t = v))
  unsub()
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/api/vms/${vmId}/terminal?token=${encodeURIComponent(t || '')}`
}
