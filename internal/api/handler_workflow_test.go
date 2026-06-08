package api

import "testing"

func TestResolveTarget(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantType   string
		wantTarget string
		wantPorts  string
	}{
		{"ip with port", "1.1.1.1:789", "ip", "1.1.1.1", "789"},
		{"plain ip", "1.1.1.1", "ip", "1.1.1.1", "top3"},
		{"cidr", "1.1.1.0/24", "ip", "1.1.1.0/24", "top3"},
		{"domain", "baidu.com", "domain", "baidu.com", ""},
		{"domain with subdomain", "www.baidu.com", "domain", "www.baidu.com", ""},
		{"https url", "https://example.com", "domain", "https://example.com", ""},
		{"http url", "http://example.com", "domain", "http://example.com", ""},
		{"url with path", "example.com/admin", "", "example.com/admin", ""},
		{"ipv6", "::1", "ip", "::1", "top3"},
		{"host with port but no protocol", "example.com:443", "ip", "example.com", "443"},
		{"empty", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wfType, target, ports := resolveTarget(tt.raw)
			if wfType != tt.wantType {
				t.Errorf("type: got %q, want %q", wfType, tt.wantType)
			}
			if target != tt.wantTarget {
				t.Errorf("target: got %q, want %q", target, tt.wantTarget)
			}
			if ports != tt.wantPorts {
				t.Errorf("ports: got %q, want %q", ports, tt.wantPorts)
			}
		})
	}
}

func TestSplitTargetList(t *testing.T) {
	got := splitTargetList("114.247.80.0/23\n111.205.118.32/27, 127.0.0.1 127.0.0.1")
	want := []string{"114.247.80.0/23", "111.205.118.32/27", "127.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("len(splitTargetList) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitTargetList[%d] = %q, want %q: %#v", i, got[i], want[i], got)
		}
	}
}

func TestInputStringSlice(t *testing.T) {
	got := inputStringSlice(map[string]interface{}{
		"targets": []interface{}{"10.0.0.0/24", "", "10.0.0.0/24", "10.0.1.0/24"},
	}, "targets")
	want := []string{"10.0.0.0/24", "10.0.1.0/24"}
	if len(got) != len(want) {
		t.Fatalf("len(inputStringSlice) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("inputStringSlice[%d] = %q, want %q: %#v", i, got[i], want[i], got)
		}
	}
}
