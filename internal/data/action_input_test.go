package data

import "testing"

func TestActionInputStrings(t *testing.T) {
	input := map[string]interface{}{
		"strings":    []string{"one", "", "  ", " two "},
		"interfaces": []interface{}{"alpha", "", 123, " beta "},
	}

	strings := ActionInputStrings(input, "strings")
	if len(strings) != 2 || strings[0] != "one" || strings[1] != " two " {
		t.Fatalf("strings = %#v, want non-empty original values", strings)
	}
	strings[0] = "mutated"
	if got := input["strings"].([]string)[0]; got != "one" {
		t.Fatalf("input mutated through returned slice: %q", got)
	}

	interfaces := ActionInputStrings(input, "interfaces")
	if len(interfaces) != 2 || interfaces[0] != "alpha" || interfaces[1] != " beta " {
		t.Fatalf("interfaces = %#v, want string values only", interfaces)
	}
	if got := ActionInputStrings(nil, "missing"); got != nil {
		t.Fatalf("nil input = %#v, want nil", got)
	}
}
