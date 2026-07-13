// Package auth — short-lived pending-2FA tokens for the two-step login (in-memory).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): TwoStepLogin; TECH(6): map,sync]
// @purpose Bridge step 1 (password verified) and step 2 (TOTP) of a 2FA login without exposing a
//
//	full session. A pending token is opaque, short-lived (5 min) and single-use.
//
// @invariants
//   - Pending tokens live only in RAM (lost on restart — user re-logs in; acceptable).
//   - Consume is single-use and rejects expired entries.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: pending2fa, two-step login, pending token, in-memory, ttl
// STRUCTURE: ▶ ┌userID┐ → ⊕ token+expiry → ⎋ ; Consume → 〈valid? unexpired?〉 → userID|0
package auth

import (
	"sync"
	"time"
)

const pendingTwoFATTL = 5 * time.Minute

// PendingTwoFA is an in-memory store of password-verified-but-not-yet-2FA'd sessions.
type PendingTwoFA struct {
	mu sync.Mutex
	m  map[string]pendingEntry
}

type pendingEntry struct {
	userID int64
	expiry time.Time
}

// NewPendingTwoFA creates an empty store.
func NewPendingTwoFA() *PendingTwoFA {
	return &PendingTwoFA{m: make(map[string]pendingEntry)}
}

// Issue records a pending 2FA session for userID and returns the opaque token to redeem.
func (p *PendingTwoFA) Issue(userID int64) (string, error) {
	tok, err := NewToken()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.sweepLocked()
	p.m[tok] = pendingEntry{userID: userID, expiry: time.Now().Add(pendingTwoFATTL)}
	p.mu.Unlock()
	return tok, nil
}

// Consume validates and removes a pending token, returning the userID (0,false if invalid/expired).
func (p *PendingTwoFA) Consume(token string) (int64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	e, ok := p.m[token]
	if !ok || time.Now().After(e.expiry) {
		delete(p.m, token)
		return 0, false
	}
	delete(p.m, token)
	return e.userID, true
}

// sweepLocked removes expired entries (called under lock).
func (p *PendingTwoFA) sweepLocked() {
	now := time.Now()
	for k, e := range p.m {
		if now.After(e.expiry) {
			delete(p.m, k)
		}
	}
}
