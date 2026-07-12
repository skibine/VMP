// Package ssh is VM Pulse's Plane-B SSH engine: it resolves per-VM credentials from the
// (armed) vault, dials the VM with golang.org/x/crypto/ssh, and enforces trust-on-first-use
// host-key verification. The returned *ssh.Client is reused by the interactive terminal and the
// one-shot snapshot runner.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): SSH,TOFU; TECH(9): x/crypto/ssh,vault]
// @purpose Give the copilot "hands": open an interactive shell and run a safe one-shot metrics
// command on any VM whose credentials are stored in the vault — without installing an agent.
// @io Dial(ctx, vmID) -> (*ssh.Client, *store.VM, error)
// @invariants
//   - Credentials are NEVER logged; only the VM id and auth_type appear in LDD traces.
//   - Host keys are verified TOFU: first connect records the fingerprint; a changed key is rejected.
//   - No credentials stored -> ErrNoCredentials (UI prompts to set them in ⚙ edit).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ssh, dial, vault, credentials, password, key, agent, TOFU, host key, Plane B
// STRUCTURE: ▶ ┌vmID┐ → ○ GetVM+GetCreds ── none ──⎋ ErrNoCredentials → ⊕ clientConfig(pw|key|agent) → ⚡ ssh.Dial(TOFU) → ⎷ *Client
package ssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// Sentinel errors. Wrap with %w so callers can errors.Is.
var (
	// ErrNoCredentials means the VM has no stored SSH credentials (user must set them first).
	ErrNoCredentials = errors.New("no ssh credentials stored for this vm")
	// ErrHostKeyChanged means the presented host key differs from the recorded TOFU fingerprint
	// (possible MITM or reinstall); the user must explicitly reset it.
	ErrHostKeyChanged = errors.New("host key changed")
)

// Dialer opens SSH connections to VMs using vault-resolved credentials.
type Dialer struct {
	st     *store.Store
	logger *slog.Logger
}

// New builds a Dialer bound to a store (with armed vault) and a logger.
func New(st *store.Store, logger *slog.Logger) *Dialer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Dialer{st: st, logger: logger}
}

// region FUNC_Dialer_Dial [DOMAIN(9): Security; CONCEPT(8): SSH; TECH(9): x/crypto/ssh]
// @purpose Open an authenticated SSH connection to a VM, enforcing TOFU host-key verification,
//
//	so both the interactive terminal and the snapshot runner can reuse it.
//
// @io (ctx, vmID) -> (*gossh.Client, *store.VM, error)
// @complexity 7
// @invariants
//   - Returns ErrNoCredentials when the VM has no stored creds (UI prompts to set them).
//   - Returns ErrHostKeyChanged (wrapped) when the host key mismatches the recorded TOFU entry.
//   - The returned *store.VM is the one dialed (caller uses it for labeling/audit).
//
// endregion FUNC_Dialer_Dial
// STRUCTURE: ▶ ┌vmID┐ → ○ GetVM ── ⊕ GetCreds?F→⎋ErrNoCreds → ⚡ clientConfig → ⊕ TOFU cb → ssh.Dial → ⎷
func (d *Dialer) Dial(ctx context.Context, vmID int64) (*gossh.Client, *store.VM, error) {
	vm, err := d.st.GetVM(ctx, vmID)
	if err != nil {
		logging.LDD(d.logger, 10, "Dial", "GET_VM_FAIL", err.Error(), slog.Int64("vm", vmID))
		return nil, nil, fmt.Errorf("ssh.Dial: load vm: %w", err)
	}

	creds, has, err := d.st.GetVMCredentials(ctx, vmID)
	if err != nil {
		logging.LDD(d.logger, 10, "Dial", "GET_CREDS_FAIL", err.Error(), slog.Int64("vm", vmID))
		return nil, &vm, fmt.Errorf("ssh.Dial: load creds: %w", err)
	}
	if !has {
		logging.LDD(d.logger, 9, "Dial", "NO_CREDS", "no stored ssh credentials", slog.Int64("vm", vmID))
		return nil, &vm, ErrNoCredentials
	}

	cfg, err := clientConfig(creds)
	if err != nil {
		logging.LDD(d.logger, 10, "Dial", "CFG_FAIL", err.Error(), slog.Int64("vm", vmID), slog.String("auth", creds.AuthType))
		return nil, &vm, fmt.Errorf("ssh.Dial: build config: %w", err)
	}
	cfg.HostKeyCallback = d.tofuCallback(vmID)
	cfg.Timeout = 12 * time.Second

	addr := dialAddr(vm)
	logging.LDD(d.logger, 7, "Dial", "DIALING", addr, slog.Int64("vm", vmID), slog.String("user", creds.SSHUser), slog.String("auth", creds.AuthType))

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		logging.LDD(d.logger, 9, "Dial", "DIAL_FAIL", err.Error(), slog.Int64("vm", vmID), slog.String("addr", addr))
		return nil, &vm, fmt.Errorf("ssh.Dial %s: %w", addr, err)
	}
	logging.LDD(d.logger, 8, "Dial", "CONNECTED", addr, slog.Int64("vm", vmID))
	return client, &vm, nil
}

// dialAddr picks the dial target: prefer the VM IP, fall back to the hostname; always VM SSH port.
func dialAddr(vm store.VM) string {
	host := vm.IP
	if host == "" {
		host = vm.Hostname
	}
	return net.JoinHostPort(host, strconv.Itoa(vm.PortSSH))
}

// region FUNC_clientConfig [DOMAIN(9): Security; CONCEPT(8): SSHAuth; TECH(9): x/crypto/ssh,agent]
// @purpose Build an ssh.ClientConfig from stored credentials, supporting password / key / agent
//
//	and any (incl. non-root) ssh user.
//
// @io (creds store.VMCredentials) -> (*gossh.ClientConfig, error)
// @complexity 6
// endregion FUNC_clientConfig
// STRUCTURE: ▶ ┌creds┐ → ◇ auth_type → 〈password|key|agent〉 → ⊕ AuthMethod → ⎷ ClientConfig
func clientConfig(creds store.VMCredentials) (*gossh.ClientConfig, error) {
	cfg := &gossh.ClientConfig{
		User:            creds.SSHUser,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), // replaced by TOFU in Dial
		Timeout:         12 * time.Second,
	}
	switch creds.AuthType {
	case "password":
		cfg.Auth = []gossh.AuthMethod{gossh.Password(creds.Secret)}
	case "key":
		signer, err := gossh.ParsePrivateKey([]byte(creds.Secret))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		cfg.Auth = []gossh.AuthMethod{gossh.PublicKeys(signer)}
	case "agent":
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("agent auth requires SSH_AUTH_SOCK (ssh-agent not running on the VM Pulse server)")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("connect ssh-agent: %w", err)
		}
		ag := agentClient(conn)
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("ssh-agent signers: %w", err)
		}
		if len(signers) == 0 {
			return nil, errors.New("ssh-agent has no keys loaded")
		}
		cfg.Auth = []gossh.AuthMethod{gossh.PublicKeys(signers...)}
	default:
		return nil, fmt.Errorf("unsupported auth_type %q", creds.AuthType)
	}
	return cfg, nil
}

// tofuCallback returns a HostKeyCallback implementing trust-on-first-use for the given VM:
// first presented key is recorded; later mismatches produce ErrHostKeyChanged.
func (d *Dialer) tofuCallback(vmID int64) gossh.HostKeyCallback {
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		fp := gossh.FingerprintSHA256(key)
		stored, ok, err := d.st.GetHostKey(context.Background(), vmID)
		if err != nil {
			return fmt.Errorf("tofu: read stored host key: %w", err)
		}
		if !ok {
			if err := d.st.SetHostKey(context.Background(), store.HostKey{VMID: vmID, Fingerprint: fp, Algo: key.Type()}); err != nil {
				return fmt.Errorf("tofu: record host key: %w", err)
			}
			logging.LDD(d.logger, 8, "tofu", "FIRST_SEEN", fp, slog.Int64("vm", vmID))
			return nil
		}
		if stored.Fingerprint != fp {
			logging.LDD(d.logger, 9, "tofu", "CHANGED", "stored="+stored.Fingerprint+" presented="+fp, slog.Int64("vm", vmID))
			return fmt.Errorf("%w: stored %s, got %s", ErrHostKeyChanged, stored.Fingerprint, fp)
		}
		return nil
	}
}
