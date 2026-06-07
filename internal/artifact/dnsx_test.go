package artifact

import (
	"testing"

	miekgdns "github.com/miekg/dns"
)

func TestDNSXTargetsDeduplicate(t *testing.T) {
	targets := dnsxTargets("example.com", DNSXInput{
		Target:  "example.com",
		Targets: []string{"www.example.com", "example.com", "  api.example.com  "},
	})

	want := []string{"example.com", "www.example.com", "api.example.com"}
	if len(targets) != len(want) {
		t.Fatalf("len(targets) = %d, want %d: %#v", len(targets), len(want), targets)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("target[%d] = %q, want %q", i, targets[i], want[i])
		}
	}
}

func TestDNSXQuestionTypes(t *testing.T) {
	types := dnsxQuestionTypes([]string{"a", "AAAA", "cname", "bad", "a"})
	want := []uint16{miekgdns.TypeA, miekgdns.TypeAAAA, miekgdns.TypeCNAME}
	if len(types) != len(want) {
		t.Fatalf("len(types) = %d, want %d: %#v", len(types), len(want), types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("type[%d] = %d, want %d", i, types[i], want[i])
		}
	}
}
