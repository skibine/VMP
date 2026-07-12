// Package store — TOFU host-key store for SSH connections (Plane B).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): HostKeyTOFU; TECH(8): database/sql,ssh]
// @purpose Remember each VM's SSH public-key fingerprint (trust-on-first-use) so a changed key
// (MITM or reinstall) is detected and rejected, while keeping the first-connect UX frictionless.
// @io vmID int64 -> Get/Set/Delete HostKey
// @invariants
//   - At most one row per VM (PK vm_id).
//   - Cascade-deleted with the VM.
//   - fingerprint is the ssh.FingerprintSHA256 of the host public key.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: host key, TOFU, fingerprint, vm_hostkeys, SSH, MITM, Plane B, ssh.FingerprintSHA256
// STRUCTURE: ▶ ┌vmID,fp┐ → ○ GetStored? ── no → ⊕ Set ── yes → 〈equal? T/O〉 → ⎷ row|changed
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// HostKey is a stored SSH host-key fingerprint for a VM (TOFU).
type HostKey struct {
	VMID        int64
	Fingerprint string // ssh.FingerprintSHA256(...) e.g. "sha256:...."
	Algo        string
}

// GetHostKey returns the stored fingerprint for a VM. ok=false when none stored (first connect).
func (s *Store) GetHostKey(ctx context.Context, vmID int64) (HostKey, bool, error) {
	var hk HostKey
	err := s.DB.QueryRowContext(ctx,
		`SELECT vm_id, fingerprint, algo FROM vm_hostkeys WHERE vm_id=?`, vmID).
		Scan(&hk.VMID, &hk.Fingerprint, &hk.Algo)
	if err == sql.ErrNoRows {
		return HostKey{}, false, nil
	}
	if err != nil {
		return HostKey{}, false, fmt.Errorf("GetHostKey: %w", err)
	}
	return hk, true, nil
}

// SetHostKey upserts the fingerprint for a VM (records TOFU on first connect).
func (s *Store) SetHostKey(ctx context.Context, hk HostKey) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO vm_hostkeys (vm_id, fingerprint, algo) VALUES (?,?,?)
ON CONFLICT(vm_id) DO UPDATE SET fingerprint=excluded.fingerprint, algo=excluded.algo,
 first_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now')`, hk.VMID, hk.Fingerprint, hk.Algo)
	if err != nil {
		return fmt.Errorf("SetHostKey: %w", err)
	}
	return nil
}

// DeleteHostKey removes the stored fingerprint for a VM (TOFU reset, e.g. after a reinstall).
func (s *Store) DeleteHostKey(ctx context.Context, vmID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM vm_hostkeys WHERE vm_id=?`, vmID)
	if err != nil {
		return fmt.Errorf("DeleteHostKey: %w", err)
	}
	return nil
}
