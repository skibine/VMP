package ssh

import (
	"testing"
)

// region FUNC_test_ParseVHosts [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(4): regex]
// @purpose Verify nginx server_name/listen pairing and apache namevhost extraction.
// @complexity 3
// endregion FUNC_test_ParseVHosts
func TestParseVHosts(t *testing.T) {
	raw := `=id=
0
=listen=
LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=447,fd=7))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=447,fd=8))
=nginx=
	    listen 80;
	    server_name example.com www.example.com;
	    listen 443 ssl;
	    server_name api.example.com;
	    server_name _;
=apache=
	    port 80 namevhost legacy.org (/etc/apache2/sites-enabled/legacy.conf:1)
	    port 443 namevhost secure.legacy.org (/etc/apache2/sites-enabled/secure.conf:2)
=caddy=`
	vl := parseVHosts(raw)
	if !vl.Root {
		t.Errorf("expected root=true (id=0)")
	}
	if vl.Server != "nginx" {
		t.Fatalf("detected server must be nginx (config yielded sites), got %q", vl.Server)
	}
	want := map[string]bool{"example.com|80": false, "www.example.com|80": false, "api.example.com|443": false, "legacy.org|80": false, "secure.legacy.org|443": false}
	for _, s := range vl.Sites {
		k := s.Name + "|" + s.Port
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected site %s:%s", s.Name, s.Port)
		}
		want[k] = true
	}
	for k, found := range want {
		if !found {
			t.Errorf("missing expected site %s", k)
		}
	}
	if len(vl.Listening) == 0 || vl.Listening[0] != "nginx:80" {
		t.Errorf("listening detection wrong: %+v", vl.Listening)
	}
	for _, s := range vl.Sites {
		if s.Name == "_" {
			t.Errorf("catch-all server_name must be excluded")
		}
	}
	t.Logf("[IMP:8][TestVHosts][RESULT] server=%s sites=%d listening=%v", vl.Server, len(vl.Sites), vl.Listening)
}

// region FUNC_test_ParseVHosts_DetectedOnly [DOMAIN(6): Testing; CONCEPT(6): Branching; TECH(4): ss]
// @purpose Box with :80/:443 served by a non-nginx/apache process whose config is not readable
// (the reported usa bug) — must report the detected server, NOT "none".
// @complexity 3
// endregion FUNC_test_ParseVHosts_DetectedOnly
func TestParseVHosts_DetectedOnly(t *testing.T) {
	raw := `=listen=
LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("caddy",pid=900,fd=3))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=900,fd=4))
=nginx=
=apache=
=caddy=`
	vl := parseVHosts(raw)
	if vl.Server != "caddy" {
		t.Fatalf("must detect caddy from ss even without readable config, got %q", vl.Server)
	}
	if len(vl.Listening) != 2 {
		t.Errorf("expected 2 listeners, got %d", len(vl.Listening))
	}
	t.Logf("[IMP:8][TestVHosts][DETECT] server=%s listening=%v", vl.Server, vl.Listening)
}

// region FUNC_test_ParseVHosts_NonRootPorts [DOMAIN(6): Testing; CONCEPT(6): Branching; TECH(4): ss]
// @purpose Reported usa bug: non-root SSH user, :80/:443 open but no process names and no readable
// config. Must report the open ports + server "unknown", NOT a misleading "none".
// @complexity 3
// endregion FUNC_test_ParseVHosts_NonRootPorts
func TestParseVHosts_NonRootPorts(t *testing.T) {
	raw := `=id=
1000
=listen=
LISTEN 0 511 0.0.0.0:80 0.0.0.0:*
LISTEN 0 511 0.0.0.0:443 0.0.0.0:*
=nginx=
=apache=
=caddy=`
	vl := parseVHosts(raw)
	if vl.Root {
		t.Errorf("expected root=false (id=1000)")
	}
	if vl.Server != "unknown" {
		t.Fatalf("non-root with open web ports must be 'unknown', got %q", vl.Server)
	}
	if len(vl.Listening) != 2 || vl.Listening[0] != ":80" {
		t.Errorf("listening ports not captured: %+v", vl.Listening)
	}
	t.Logf("[IMP:8][TestVHosts][NONROOT] server=%s listening=%v", vl.Server, vl.Listening)
}

// region FUNC_test_ParseVHosts_None [DOMAIN(6): Testing; CONCEPT(6]: Branching; TECH(3]: empty]
// @purpose No web server -> Server="none", empty sites (not an error).
// @complexity 2
// endregion FUNC_test_ParseVHosts_None
func TestParseVHosts_None(t *testing.T) {
	vl := parseVHosts("=id=\n0\n=listen=\n=nginx=\n=apache=\n=caddy=\ncommand not found\n")
	if vl.Server != "none" || len(vl.Sites) != 0 {
		t.Fatalf("expected none/empty, got %+v", vl)
	}
	t.Logf("[IMP:8][TestVHosts][NONE] server=%s", vl.Server)
}
