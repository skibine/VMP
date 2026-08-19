// Package auth — sliding-window rate limiter (login brute-force + DoS damper).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): RateLimit; TECH(7): sync,map]
// @purpose Bound authentication attempts per IP+username so the unauthenticated login endpoint
//
//	can neither be brute-forced nor used as an argon2-allocation DoS (each attempt burns
//	~64MB; see the audit). RAM-only by design: single-operator deployment, restart clears.
//
// @io NewLimiter(max int, window time.Duration) -> *Limiter ; Allow(key) bool ; Clear(key)
// @invariants
//   - Allow is goroutine-safe and NEVER blocks (mutex-guarded slice prune).
//   - Clear on SUCCESSFUL login forgets the key (one typo streak does not lock the operator out).
//   - Pruning is lazy (on access); a stale idle map entry costs memory, not correctness.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: rate limit, brute force, login, sliding window, argon2 dos, 429
// STRUCTURE: ▶ ┌key┐ → ○ prune>window → ◇ len<max? → ⊕ append now → ⎷ allow|deny
package auth

import (
	"sync"
	"time"
)

// Limiter is a sliding-window attempt counter per key (ip|username).
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string][]time.Time
}

// NewLimiter builds a limiter allowing `max` attempts per `window` per key.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, seen: map[string][]time.Time{}}
}

// Allow records an attempt and reports whether it fits the window.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.seen[key]
	kept := times[:0]
	for _, t := range times {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	// Opportunistic full prune: the map only grows via distinct keys; at operator scale this
	// is a handful of entries, so a periodic sweep keeps memory bounded without a goroutine.
	if len(l.seen) > 1024 {
		for k, v := range l.seen {
			alive := false
			for _, t := range v {
				if now.Sub(t) < l.window {
					alive = true
					break
				}
			}
			if !alive {
				delete(l.seen, k)
			}
		}
	}
	return true
}

// Clear forgets a key (call on successful login).
func (l *Limiter) Clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, key)
}
