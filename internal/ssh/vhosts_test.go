package ssh

import (
	"testing"
)

// region FUNC_test_ParseVHosts [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(4): regex]
// @purpose Verify nginx server_name/listen pairing and apache namevhost extraction.
// @complexity 3
// endregion FUNC_test_ParseVHosts
func TestParseVHosts(t *testing.T) {
	raw := `=nginx=
	    listen 80;
	    server_name example.com www.example.com;
	    listen 443 ssl;
	    server_name api.example.com;
	    server_name _;
=apache=
	    port 80 namevhost legacy.org (/etc/apache2/sites-enabled/legacy.conf:1)
	    port 443 namevhost secure.legacy.org (/etc/apache2/sites-enabled/secure.conf:2)
`
	vl := parseVHosts(raw)
	if vl.Server != "nginx" {
		t.Fatalf("first detected server must be nginx (it appears first), got %q", vl.Server)
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
	// catch-all "_" must be excluded
	for _, s := range vl.Sites {
		if s.Name == "_" {
			t.Errorf("catch-all server_name must be excluded")
		}
	}
	t.Logf("[IMP:8][TestVHosts][RESULT] server=%s sites=%d", vl.Server, len(vl.Sites))
}

// region FUNC_test_ParseVHosts_None [DOMAIN(6): Testing; CONCEPT(6]: Branching; TECH(3]: empty]
// @purpose No web server -> Server="none", empty sites (not an error).
// @complexity 2
// endregion FUNC_test_ParseVHosts_None
func TestParseVHosts_None(t *testing.T) {
	vl := parseVHosts("=nginx=\n=apache=\ncommand not found\n")
	if vl.Server != "none" || len(vl.Sites) != 0 {
		t.Fatalf("expected none/empty, got %+v", vl)
	}
	t.Logf("[IMP:8][TestVHosts][NONE] server=%s", vl.Server)
}
