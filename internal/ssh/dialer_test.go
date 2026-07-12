// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): SSHDial,TOFU; TECH(8): go test,x/crypto/ssh]
// @purpose Verify clientConfig auth builders, TOFU host-key callback, and an end-to-end Dial
//
//	against an in-process ssh server (password auth). Prints [IMP:7-10] (Semantic Trace).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, ssh, dialer, clientConfig, TOFU, password, key, agent, embedded server
// STRUCTURE: ▶ ┌store+creds┐ → ◇ auth_type → 〈build/match/mismatch〉 → ⚡ embedded server Dial → ⎷
package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/skibine/vm-pulse/internal/crypto"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

func testDialer(t *testing.T) (*Dialer, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logr := logging.Setup(slog.LevelDebug, buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "ssh.sqlite"), logr)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	salt, _ := crypto.GenerateSalt()
	s.SetVault(crypto.NewVault("pass", salt))
	return New(s, logr), buf
}

func atoiOr(s string, def int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func TestClientConfig_PasswordKeyAgent(t *testing.T) {
	// password
	cfg, err := clientConfig(store.VMCredentials{SSHUser: "u", AuthType: "password", Secret: "pw"})
	if err != nil || cfg.User != "u" {
		t.Fatalf("password cfg: %v %v", cfg, err)
	}
	// key: generate an unencrypted ed25519 PEM
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		// MarshalPrivateKey may not exist in older versions; fall back to x509 PEM block.
		t.Fatalf("marshal private key: %v", err)
	}
	cfg, err = clientConfig(store.VMCredentials{SSHUser: "u", AuthType: "key", Secret: string(pem.EncodeToMemory(pemBlock))})
	if err != nil {
		t.Fatalf("key cfg: %v", err)
	}
	// agent without SSH_AUTH_SOCK -> error
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := clientConfig(store.VMCredentials{SSHUser: "u", AuthType: "agent"}); err == nil {
		t.Fatalf("expected error for agent without SSH_AUTH_SOCK")
	}
	// unsupported
	if _, err := clientConfig(store.VMCredentials{SSHUser: "u", AuthType: "weird"}); err == nil {
		t.Fatalf("expected error for unsupported auth_type")
	}
}

func TestTOFUCallback(t *testing.T) {
	d, _ := testDialer(t)
	ctx := context.Background()
	vmID, _ := d.st.CreateVM(ctx, store.VM{Name: "tofu", Hostname: "h", PortSSH: 22})

	// two distinct host public keys
	pubA, _, _ := ed25519.GenerateKey(crand.Reader)
	pubB, _, _ := ed25519.GenerateKey(crand.Reader)
	keyA, _ := gossh.NewPublicKey(pubA)
	keyB, _ := gossh.NewPublicKey(pubB)
	cb := d.tofuCallback(vmID)

	// first call (A) -> trust + record
	if err := cb("h", nil, keyA); err != nil {
		t.Fatalf("first TOFU: %v", err)
	}
	stored, ok, _ := d.st.GetHostKey(ctx, vmID)
	if !ok || stored.Fingerprint != gossh.FingerprintSHA256(keyA) {
		t.Fatalf("TOFU did not record A: %+v", stored)
	}
	// repeat A -> ok
	if err := cb("h", nil, keyA); err != nil {
		t.Fatalf("repeat TOFU A: %v", err)
	}
	// B presented -> changed -> ErrHostKeyChanged
	err := cb("h", nil, keyB)
	if err == nil || !strings.Contains(err.Error(), "host key changed") {
		t.Fatalf("expected host key changed error, got %v", err)
	}
}

// startSSHServer starts an in-process ssh server (password "pass" for user "u") returning its
// address and a stop function. hostSigner signs the server host key.
func startSSHServer(t *testing.T, hostSigner gossh.Signer) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &gossh.ServerConfig{PasswordCallback: func(c gossh.ConnMetadata, pw []byte) (*gossh.Permissions, error) {
		if c.User() == "u" && string(pw) == "pass" {
			return nil, nil
		}
		return nil, errors.New("bad creds")
	}}
	cfg.AddHostKey(hostSigner)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				sc, chans, _, err := gossh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				for newCh := range chans {
					_ = newCh.Reject(gossh.Prohibited, "no channels")
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestDial_PasswordAuth_HappyAndTOFU(t *testing.T) {
	hostPub, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("host key gen: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	addr, stop := startSSHServer(t, hostSigner)
	t.Cleanup(stop)
	host, port, _ := net.SplitHostPort(addr)

	d, buf := testDialer(t)
	ctx := context.Background()
	vmID, _ := d.st.CreateVM(ctx, store.VM{Name: "srv", Hostname: host, IP: host, PortSSH: atoiOr(port, 0)})
	_ = d.st.SetVMCredentials(ctx, store.VMCredentials{VMID: vmID, SSHUser: "u", AuthType: "password", Secret: "pass"})

	// first Dial: no creds path not hit; TOFU records host key
	client, _, err := d.Dial(ctx, vmID)
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	client.Close()
	hk, ok, _ := d.st.GetHostKey(ctx, vmID)
	hostSSHPub, _ := gossh.NewPublicKey(hostPub)
	if !ok || hk.Fingerprint != gossh.FingerprintSHA256(hostSSHPub) {
		t.Fatalf("TOFU host key not recorded: %+v", hk)
	}
	// second Dial: TOFU match -> ok
	c2, _, err := d.Dial(ctx, vmID)
	if err != nil {
		t.Fatalf("second Dial (TOFU match): %v", err)
	}
	c2.Close()

	// no creds -> ErrNoCredentials
	vmID2, _ := d.st.CreateVM(ctx, store.VM{Name: "nocreds", Hostname: host, IP: host, PortSSH: atoiOr(port, 0)})
	if _, _, err := d.Dial(ctx, vmID2); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}

	// Semantic Trace: expect an [IMP:8] CONNECTED line for the happy dial.
	if !strings.Contains(buf.String(), "[IMP:8][Dial][CONNECTED]") {
		t.Errorf("Anti-Illusion: expected [IMP:8][Dial][CONNECTED] in trace, got:\n%s", buf.String())
	}
}
