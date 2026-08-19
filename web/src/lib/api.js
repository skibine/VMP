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
  // cache: 'no-store' — API responses must NEVER be served from browser cache, otherwise list
  // changes (add/delete/archive) only appear after a hard refresh (the matrix/sidebar went stale).
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' })
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
  changePassword: (currentPassword, newPassword) =>
    req('/api/auth/password', { method: 'PUT', body: { current_password: currentPassword, new_password: newPassword } }),
  twoFASetup: () => req('/api/auth/2fa/setup', { method: 'POST' }),
  twoFAEnable: (code) => req('/api/auth/2fa/enable', { method: 'POST', body: { code } }),
  twoFADisable: (password) => req('/api/auth/2fa/disable', { method: 'POST', body: { password } }),
  // Alerts: channels (delivery) + rules (criteria) + fired alerts.
  listChannels: () => req('/api/channels'),
  createChannel: (c) => req('/api/channels', { method: 'POST', body: c }),
  updateChannel: (id, c) => req('/api/channels/' + id, { method: 'PUT', body: c }),
  deleteChannel: (id) => req('/api/channels/' + id, { method: 'DELETE' }),
  testChannel: (id) => req('/api/channels/' + id + '/test', { method: 'POST' }),
  listNotifications: () => req('/api/notifications'),
  markNotificationRead: (id) => req('/api/notifications/' + id + '/read', { method: 'POST' }),
  markAllNotificationsRead: () => req('/api/notifications/read-all', { method: 'POST' }),
  listAlertRules: () => req('/api/alert-rules'),
  createAlertRule: (r) => req('/api/alert-rules', { method: 'POST', body: r }),
  deleteAlertRule: (id) => req('/api/alert-rules/' + id, { method: 'DELETE' }),
  attachChannel: (ruleId, channelId) => req('/api/alert-rules/' + ruleId + '/channels', { method: 'POST', body: { channel_id: channelId } }),
  listRuleChannels: (ruleId) => req('/api/alert-rules/' + ruleId + '/channels'),
  listFiredAlerts: (limit) => req('/api/alerts' + (limit ? '?limit=' + limit : '')),
  listAlertMutes: () => req('/api/alert-mutes'),
  setAlertMute: (id, on) => req('/api/vms/' + id + '/alert-mute', { method: 'POST', body: { on } }),
  vmAlertChannels: (id) => req('/api/vms/' + id + '/alert-channels'),
  setVMAlertChannels: (id, channelIds) => req('/api/vms/' + id + '/alert-channels', { method: 'PUT', body: { channel_ids: channelIds } }),
  allVMAlertChannels: () => req('/api/vms/alert-channels'),
  allDomainHealth: () => req('/api/domains/health'),
  domainIPInfo: (id) => req('/api/domains/' + id + '/ipinfo'),
  domainPortScan: (id) => req('/api/domains/' + id + '/portscan'),
  domainIntel: (id) => req('/api/domains/' + id + '/intel'),
  resolveTelegramChatId: (token) => req('/api/channels/telegram/resolve', { method: 'POST', body: { bot_token: token } }),
  version: () => req('/api/version'),
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
  deepScan: (id, scope) => req('/api/vms/' + id + '/deepscan?scope=' + (scope || 'fast'), { method: 'POST' }),
  exposures: (id) => req('/api/vms/' + id + '/exposures'),
  exposuresScanAll: () => req('/api/exposures/scan-all', { method: 'POST' }),
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
  listDomainReminders: (id) => req('/api/domains/' + id + '/reminders'),
  createDomainReminder: (id, r) => req('/api/domains/' + id + '/reminders', { method: 'POST', body: r }),
  deleteDomainReminder: (rid) => req('/api/reminders/' + rid, { method: 'DELETE' }),
  createDomain: (d) => req('/api/domains', { method: 'POST', body: d }),
  deleteDomain: (id) => req('/api/domains/' + id, { method: 'DELETE' }),
  domainInfo: (id) => req('/api/domains/' + id + '/info'),
  domainHealth: (id) => req('/api/domains/' + id + '/health'),
  setDnsBaseline: (id) => req('/api/domains/' + id + '/dns-baseline', { method: 'POST' }),
  setAIAccess: (id, enabled) => req('/api/vms/' + id + '/ai-access', { method: 'PUT', body: { enabled } }),
  vmHealth: (id) => req('/api/vms/' + id + '/health'),
  vmResults: (id) => req('/api/vms/' + id + '/results'),
  aiChat: (message, history) => req('/api/ai/chat', { method: 'POST', body: { message, history } }),
  aiHistory: () => req('/api/ai/history'),
  clearAIHistory: () => req('/api/ai/history', { method: 'DELETE' }),
  shutdownServer: () => req('/api/server/shutdown', { method: 'POST' }),
  securityStatus: () => req('/api/security/status'),
  auditEvents: (params) => {
    const q = Object.entries(params || {}).filter(([, v]) => v !== '' && v != null).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&')
    return req('/api/audit' + (q ? '?' + q : ''))
  },
  clearAudit: (before) => req('/api/audit' + (before ? '?before=' + encodeURIComponent(before) : ''), { method: 'DELETE' }),
  notificationsAll: (params) => {
    const q = Object.entries(params || {}).filter(([, v]) => v !== '' && v != null).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&')
    return req('/api/notifications/all' + (q ? '?' + q : ''))
  },
  clearNotifications: (scope) => req('/api/notifications?scope=' + encodeURIComponent(scope || 'read'), { method: 'DELETE' }),


  // Settings
  getAISettings: () => req('/api/settings/ai'),
  updateAISettings: (cfg) => req('/api/settings/ai', { method: 'PUT', body: cfg }),
  getLocale: () => req('/api/settings/locale'),
  setLocale: (locale) => req('/api/settings/locale', { method: 'PUT', body: { locale } }),
  // AI model discovery: provider /models list + localhost LLM detection.
  aiModels: () => req('/api/ai/models'),
  probeLocalAI: () => req('/api/ai/probe-local'),
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
