// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): WebSSHAPI; TECH(8): go test,httptest,ssh]
// @purpose Verify snapshot no-creds (409), host-key reset, and an end-to-end snapshot over an
//
//	in-process exec ssh server (parses canned free/df/uptime output). Prints [IMP:7-10].
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, web-ssh, snapshot, hostkey, reset, exec ssh server, 409, integration
// STRUCTURE: ▶ ┌server+vm+creds┐ → ◇ (no-creds|reset|exec) → ⚡ POST /snapshot → 〈200/409 + parsed〉 → ⎋
package api

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/skibine/vm-pulse/internal/store"
)

// startExecSSHServer starts an in-process ssh server that responds to any "exec" request with the
// canned output (mimicking free/df/uptime/loadavg/nproc), returning its address and a stop func.
func startExecSSHServer(t *testing.T, hostSigner gossh.Signer, canned string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &gossh.ServerConfig{PasswordCallback: func(m gossh.ConnMetadata, p []byte) (*gossh.Permissions, error) {
		if m.User() == "u" && string(p) == "pass" {
			return nil, nil
		}
		return nil, errors.New("bad creds")
	}}
	cfg.AddHostKey(hostSigner)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, chans, reqs, err := gossh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go gossh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(gossh.UnknownChannelType, "")
						continue
					}
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func(ch gossh.Channel, reqs <-chan *gossh.Request) {
						defer ch.Close()
						for req := range reqs {
							if req.Type == "exec" {
								req.Reply(true, nil)
								_, _ = ch.Write([]byte(canned))
								_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ C uint32 }{0}))
								return
							}
							req.Reply(false, nil)
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

const cannedSnapshot = "=mem=\nMem:           1987        1023         234\n=up=\n 12:30:01 up 10 days,  3:42,  2 users\n=load=\n0.10 0.05 0.01 1/123 4567\n=cpu=\n4\n"

func seedVMWithCreds(t *testing.T, srv *Server, host string, port int) int64 {
	t.Helper()
	rec := do(srv, http.MethodPost, "/api/vms",
		`{"name":"srv","hostname":"`+host+`","ip":"`+host+`","port_ssh":`+strconv.Itoa(port)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create vm: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&res)
	_ = srv.store.SetVMCredentials(context.Background(), store.VMCredentials{
		VMID: res.ID, SSHUser: "u", AuthType: "password", Secret: "pass",
	})
	return res.ID
}

func TestWebSSH_SnapshotNoCreds(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(srv, http.MethodPost, "/api/vms",
		`{"name":"nc","hostname":"h","port_ssh":22}`)
	var res struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&res)

	rec = do(srv, http.MethodPost, "/api/vms/"+strconv.FormatInt(res.ID, 10)+"/snapshot", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 no creds, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no_ssh_credentials") {
		t.Fatalf("want no_ssh_credentials reason, got %s", rec.Body.String())
	}
}

func TestWebSSH_SnapshotIntegration(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, stop := startExecSSHServer(t, hostSigner, cannedSnapshot)
	t.Cleanup(stop)
	host, port, _ := net.SplitHostPort(addr)

	srv, buf := newServer(t)
	vmID := seedVMWithCreds(t, srv, host, atoiT(port))

	rec := do(srv, http.MethodPost, "/api/vms/"+strconv.FormatInt(vmID, 10)+"/snapshot", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}
	var snap map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&snap)
	if int(snap["mem_total_mb"].(float64)) != 1987 || int(snap["mem_used_mb"].(float64)) != 1023 {
		t.Errorf("mem parse wrong: %+v", snap)
	}
	if int(snap["cpu_count"].(float64)) != 4 {
		t.Errorf("cpu parse wrong: %+v", snap)
	}
	if !strings.HasPrefix(snap["uptime"].(string), "10 days") {
		t.Errorf("uptime wrong: %+v", snap)
	}
	if !strings.Contains(buf.String(), "[IMP:8][Snapshot][OK]") {
		t.Errorf("Anti-Illusion: expected [IMP:8][Snapshot][OK] in trace, got:\n%s", buf.String())
	}
}

func TestWebSSH_HostKeyReset(t *testing.T) {
	srv, _ := newServer(t)
	vmID := seedVMWithCreds(t, srv, "127.0.0.1", 22)
	_ = srv.store.SetHostKey(context.Background(), store.HostKey{VMID: vmID, Fingerprint: "sha256:X"})
	if _, ok, _ := srv.store.GetHostKey(context.Background(), vmID); !ok {
		t.Fatal("precondition: host key should be set")
	}
	rec := do(srv, http.MethodDelete, "/api/vms/"+strconv.FormatInt(vmID, 10)+"/hostkey", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := srv.store.GetHostKey(context.Background(), vmID); ok {
		t.Fatal("host key still present after reset")
	}
}

func atoiT(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
