package data

import "testing"

func TestActionInputStrings(t *testing.T) {
	input := map[string]interface{}{
		"scalar":     " one ",
		"strings":    []string{"one", "", "  ", " two ", "one"},
		"interfaces": []interface{}{"alpha", "", 123, " beta ", "alpha"},
	}

	scalar := ActionInputStrings(input, "scalar")
	if len(scalar) != 1 || scalar[0] != "one" {
		t.Fatalf("scalar = %#v, want trimmed string value", scalar)
	}

	strings := ActionInputStrings(input, "strings")
	if len(strings) != 3 || strings[0] != "one" || strings[1] != "two" || strings[2] != "one" {
		t.Fatalf("strings = %#v, want trimmed non-empty values without dedup", strings)
	}
	strings[0] = "mutated"
	if got := input["strings"].([]string)[0]; got != "one" {
		t.Fatalf("input mutated through returned slice: %q", got)
	}

	interfaces := ActionInputStrings(input, "interfaces")
	if len(interfaces) != 3 || interfaces[0] != "alpha" || interfaces[1] != "beta" || interfaces[2] != "alpha" {
		t.Fatalf("interfaces = %#v, want string values only without dedup", interfaces)
	}
	if got := ActionInputStrings(nil, "missing"); got != nil {
		t.Fatalf("nil input = %#v, want nil", got)
	}
}

func TestCleanStringsDedupIsExplicit(t *testing.T) {
	values := []string{" one ", "", "two", "one", " two "}
	kept := CleanStrings(values, false)
	if len(kept) != 4 || kept[0] != "one" || kept[1] != "two" || kept[2] != "one" || kept[3] != "two" {
		t.Fatalf("CleanStrings dedup=false = %#v, want trimmed values with duplicates", kept)
	}
	deduped := CleanStrings(values, true)
	if len(deduped) != 2 || deduped[0] != "one" || deduped[1] != "two" {
		t.Fatalf("CleanStrings dedup=true = %#v, want first occurrence order", deduped)
	}
}

func TestSplitListCleansAndDeduplicates(t *testing.T) {
	got := SplitList("alpha, beta\nalpha\tgamma  beta", true)
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("SplitList len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SplitList[%d] = %q, want %q: %#v", i, got[i], want[i], got)
		}
	}
}
