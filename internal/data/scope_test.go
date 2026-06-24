package data

import "testing"

func TestScopeSetAllowsHostsURLsCIDRsAndSubdomains(t *testing.T) {
	scope := NewScopeSet([]string{"example.com", "10.0.0.0/24", "2001:db8::1"})
	for _, value := range []string{
		"https://api.example.com/login",
		"example.com:443",
		"http://10.0.0.12:8080",
		"[2001:db8::1]:443",
	} {
		if !scope.Contains(value) {
			t.Fatalf("scope should contain %q", value)
		}
	}
	for _, value := range []string{"https://example.net", "10.0.1.12"} {
		if scope.Contains(value) {
			t.Fatalf("scope should not contain %q", value)
		}
	}
}

func TestScopeSetLoopbackRequiresExplicitScope(t *testing.T) {
	scope := NewScopeSet([]string{"example.com"})
	if scope.AllowsAll([]string{"http://127.0.0.1:8080"}) {
		t.Fatalf("loopback should be rejected unless explicitly scoped")
	}
	scope = NewScopeSet([]string{"127.0.0.1"})
	if !scope.AllowsAll([]string{"http://127.0.0.1:8080"}) {
		t.Fatalf("loopback should be allowed when explicitly scoped")
	}
}

func TestSeverityRankAcceptsInformationalAlias(t *testing.T) {
	if SeverityRank("informational") != SeverityRank("info") {
		t.Fatalf("informational severity should rank as info")
	}
}
