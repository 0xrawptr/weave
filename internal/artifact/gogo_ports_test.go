package artifact

import (
	"testing"

	gogopkg "github.com/chainreactors/gogo/v2/pkg"
)

func TestNormalizeGogoPorts(t *testing.T) {
	tests := map[string]string{
		"":        "top3",
		"default": "top3",
		"top100":  "top3",
		"top1000": "top3",
		"80,443":  "80,443",
	}
	for input, want := range tests {
		if got := normalizeGogoPorts(input); got != want {
			t.Fatalf("normalizeGogoPorts(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValidateGogoPorts(t *testing.T) {
	if err := gogopkg.LoadPortConfig(""); err != nil {
		t.Fatalf("load gogo port config: %v", err)
	}
	if err := validateGogoPorts(normalizeGogoPorts("top1000")); err != nil {
		t.Fatalf("normalized top1000 should validate: %v", err)
	}
	if err := validateGogoPorts("80,443,8080"); err != nil {
		t.Fatalf("explicit ports should validate: %v", err)
	}
	if err := validateGogoPorts("definitely-not-a-port-preset"); err == nil {
		t.Fatalf("unknown port preset should fail validation")
	}
}
