// Package store — per-VM SSH credentials (Plane B vault). The secret is encrypted at rest.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): VMCreds; TECH(8): database/sql,vault]
// @purpose Store per-VM SSH credentials (user, auth_type, password OR private key) encrypted by
//
//	the vault. Decryption is in-RAM only (GetVMCredentials), consumed by web-SSH later.
//
// @invariants
//   - secret is vault-encrypted at rest; never returned by read APIs that cross the wire.
//   - One row per VM (PK vm_id); cascade-deleted with the VM.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: vm_credentials, SSH, credentials, vault, encrypted, GetVMCredentials, Plane B
// STRUCTURE: ▶ ┌vm,user,type,secret┐ → ○ encCol(secret) → ⎋ ; Get → decCol → RAM
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// VMCredentials is the decrypted form (RAM only).
type VMCredentials struct {
	VMID          int64
	SSHUser       string
	AuthType      string // password | key | agent
	Secret        string // password OR private key (plaintext only in RAM)
	KeyPassphrase string // passphrase for passphrase-protected keys (empty = no passphrase)
	SudoPassword  string // optional sudo password for non-interactive privileged RunCommand (empty = none)
	Inventory     string // last successful SSH inventory JSON (non-secret facts)
}

// Validate enforces non-empty user for password/key auth (agent needs no secret).
func (c VMCredentials) Validate() error {
	if c.AuthType != "password" && c.AuthType != "key" && c.AuthType != "agent" {
		return ValidationError{Field: "auth_type", Reason: "must be password|key|agent"}
	}
	if c.AuthType != "agent" {
		if strings.TrimSpace(c.SSHUser) == "" {
			return ValidationError{Field: "ssh_user", Reason: "required"}
		}
		if strings.TrimSpace(c.Secret) == "" {
			return ValidationError{Field: "secret", Reason: "required for " + c.AuthType}
		}
	}
	return nil
}

// SetVMCredentials upserts credentials for a VM (secret encrypted at rest).
func (s *Store) SetVMCredentials(ctx context.Context, c VMCredentials) error {
	if err := c.Validate(); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO vm_credentials (vm_id, ssh_user, auth_type, secret, key_passphrase, sudo_password) VALUES (?,?,?,?,?,?)
ON CONFLICT(vm_id) DO UPDATE SET ssh_user=excluded.ssh_user, auth_type=excluded.auth_type,
 secret=excluded.secret, key_passphrase=excluded.key_passphrase, sudo_password=excluded.sudo_password,
 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`,
		c.VMID, c.SSHUser, c.AuthType, s.encCol(c.Secret), s.encCol(c.KeyPassphrase), s.encCol(c.SudoPassword))
	if err != nil {
		return fmt.Errorf("SetVMCredentials: %w", err)
	}
	return nil
}

// GetVMCredentials returns the decrypted credentials for a VM. ok=false when none stored.
func (s *Store) GetVMCredentials(ctx context.Context, vmID int64) (VMCredentials, bool, error) {
	var c VMCredentials
	var rawSecret, rawPass, rawSudo string
	err := s.DB.QueryRowContext(ctx,
		`SELECT vm_id, ssh_user, auth_type, secret, key_passphrase, sudo_password, inventory FROM vm_credentials WHERE vm_id=?`, vmID).
		Scan(&c.VMID, &c.SSHUser, &c.AuthType, &rawSecret, &rawPass, &rawSudo, &c.Inventory)
	if err == sql.ErrNoRows {
		return VMCredentials{}, false, nil
	}
	if err != nil {
		return VMCredentials{}, false, fmt.Errorf("GetVMCredentials: %w", err)
	}
	c.Secret = s.decCol(rawSecret)
	c.KeyPassphrase = s.decCol(rawPass)
	c.SudoPassword = s.decCol(rawSudo)
	return c, true, nil
}

// SetVMInventory persists the last successful SSH inventory JSON for a VM (non-secret facts only).
func (s *Store) SetVMInventory(ctx context.Context, vmID int64, inventoryJSON string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE vm_credentials SET inventory=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE vm_id=?`,
		inventoryJSON, vmID)
	if err != nil {
		return fmt.Errorf("SetVMInventory: %w", err)
	}
	return nil
}

// DeleteVMCredentials removes stored credentials for a VM.
func (s *Store) DeleteVMCredentials(ctx context.Context, vmID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM vm_credentials WHERE vm_id=?`, vmID)
	if err != nil {
		return fmt.Errorf("DeleteVMCredentials: %w", err)
	}
	return nil
}
