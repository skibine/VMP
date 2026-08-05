// region MODULE_CONTRACT_test [DOMAIN(6): Testing; CONCEPT(7): RDAP; TECH(5): go test]
// @purpose Verify the pure RDAP helpers (suffix -> base mapping, vcard fn extraction) that need no
// @purpose network. The live path is exercised by TestDomainInfo_Live where available.
// @complexity 2
// endregion MODULE_CONTRACT_test
package monitor

import "testing"

func TestRDAPSuffix(t *testing.T) {
	m := map[string]string{
		"pro":   "https://rdap.identitydigital.services/rdap/",
		"com":   "https://rdap.verisign.com/com/v1/",
		"co.uk": "https://rdap.nominet.uk/rdap/",
	}
	cases := []struct {
		domain, want string
	}{
		{"example.pro", "https://rdap.identitydigital.services/rdap/"},
		{"example.com", "https://rdap.verisign.com/com/v1/"},
		{"example.co.uk", "https://rdap.nominet.uk/rdap/"}, // longest suffix must win
	}
	for _, c := range cases {
		got, ok := rdapSuffix(m, c.domain)
		if !ok || got != c.want {
			t.Errorf("rdapSuffix(%q) = %q,%v want %q", c.domain, got, ok, c.want)
		}
	}
	if got, ok := rdapSuffix(m, "example.io"); ok {
		t.Errorf("rdapSuffix(example.io) unexpected match %q", got)
	}
	t.Logf("[IMP:8][TestRDAPSuffix][RESULT] suffix mapping ok, longest-match wins")
}

func TestRDAPVcardFN(t *testing.T) {
	v := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "NameSilo,LLC"},
			[]any{"kind", map[string]any{}, "text", "individual"},
		},
	}
	if got := rdapVcardFN(v); got != "NameSilo,LLC" {
		t.Errorf("rdapVcardFN = %q want NameSilo,LLC", got)
	}
	if got := rdapVcardFN([]any{"vcard", "not-a-list"}); got != "" {
		t.Errorf("rdapVcardFN(malformed) = %q want empty", got)
	}
	t.Logf("[IMP:8][TestRDAPVcardFN][RESULT] fn extraction ok, malformed safe")
}
