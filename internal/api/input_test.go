package api

import "testing"

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

func TestCleanStringSlice(t *testing.T) {
	got := cleanStringSlice([]string{"10.0.0.0/24", "", "10.0.0.0/24", " 10.0.1.0/24 "})
	want := []string{"10.0.0.0/24", "10.0.1.0/24"}
	if len(got) != len(want) {
		t.Fatalf("len(cleanStringSlice) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cleanStringSlice[%d] = %q, want %q: %#v", i, got[i], want[i], got)
		}
	}
}
