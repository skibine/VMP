// region MODULE_CONTRACT [DOMAIN(7): UI; CONCEPT(8): AlertCoverage; TECH(7): svelte/store]
// @purpose Single source of truth for "is this server under a live alert?" Shared by the fleet
// matrix, the sidebar, and the VM detail page so the bell is computed ONE way everywhere and
// fetched ONCE (batch) instead of N+1 per component.
// @invariants
//   - A transient fetch failure NEVER blanks the bells — last-known coverage is kept.
//   - isAlerted matches the evaluator: covered = (fleet rule && not muted) OR scoped rule; AND the
//     server has >=1 channel. Scoped rules override mute (a server's own rule always fires).
// endregion MODULE_CONTRACT
// GREP_SUMMARY: alert coverage, bell, isAlerted, fleetOn, muted, scoped, vmChannels, batch
// STRUCTURE: ▶ ┌rules+mutes+batch┐ → ○ Promise.all → ⊕ coverage store → 〈derived alertedIds〉 → ⎋ bells
import { writable, get } from 'svelte/store'
import { api } from './api.js'
import { alertRevision } from './stores.js'

export const coverage = writable({
  fleetOn: false,
  fleetRule: null, // the fleet-wide liveness rule object (vm_id null) — needed to delete it on "all off"
  mutedIds: new Set(),
  scopedIds: new Set(),
  vmChannels: new Map(), // vmId -> [channelId,...]
  channels: [], // full channel objects (for pickers)
  loaded: false,
})

// vmCovered: does a liveness rule cover this server? (fleet-unmuted OR its own scoped rule). Scoped
// rules override mute (matches the evaluator).
export function vmCovered(vmId, c) {
  return (c.fleetOn && !c.mutedIds.has(vmId)) || c.scopedIds.has(vmId)
}

// vmAlerted: will this server actually notify someone? = covered AND it has >=1 delivery channel
// attached (in-app, telegram or webhook — all are optional, user-chosen in the bell picker). This is
// the single "is the bell on?" rule shared by the sidebar, fleet matrix and VM detail.
export function vmAlerted(vmId, c) {
  return vmCovered(vmId, c) && (c.vmChannels.get(vmId) || []).length > 0
}

// refreshAlertCoverage reloads rules + mutes + the batch channel map + the channel list in one pass.
// On ANY failure it keeps the last-known coverage (never blanks the bells) — see W5 in the review.
let lastCoverage = get(coverage)
coverage.subscribe((v) => (lastCoverage = v))
export async function refreshAlertCoverage() {
  try {
    const [rules, chs, mutes, vmCh] = await Promise.all([
      api.listAlertRules(),
      api.listChannels(),
      api.listAlertMutes(),
      api.allVMAlertChannels(),
    ])
    const all = rules || []
    const fleetRule = all.find((r) => r.vm_id == null && r.check_type === 'liveness') || null
    const scopedIds = new Set(all.filter((r) => r.vm_id != null && r.check_type === 'liveness').map((r) => r.vm_id))
    const mutedIds = new Set((mutes && mutes.vm_ids) || [])
    const vmChannels = new Map()
    for (const [k, v] of Object.entries(vmCh || {})) vmChannels.set(Number(k), v)
    coverage.set({ fleetOn: !!fleetRule, fleetRule, mutedIds, scopedIds, vmChannels, channels: chs || [], loaded: true })
  } catch (_) {
    // keep last-known — a transient API hiccup must not hide every bell.
  }
}

// Auto-refresh whenever any bell/channel mutation bumps the global alertRevision.
alertRevision.subscribe(() => {
  refreshAlertCoverage()
})
