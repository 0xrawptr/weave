package data

import (
	"testing"
)

func TestGenerateID(t *testing.T) {
	tests := []struct {
		parts    []string
		wantSame []string // should produce same ID as this
	}{
		{parts: []string{"ip", "1.1.1.1"}, wantSame: []string{"ip", "1.1.1.1"}},
		{parts: []string{"ip", "scanA", "1.1.1.1"}},
		{parts: []string{"port", "scanA", "1.1.1.1", "80"}},
		{parts: []string{"target", "202.205.160.0/20"}},
	}
	for _, tt := range tests {
		t.Run(tt.parts[0], func(t *testing.T) {
			id1 := GenerateID(tt.parts...)
			id2 := GenerateID(tt.parts...)
			if id1 != id2 {
				t.Errorf("GenerateID not stable: %s != %s", id1, id2)
			}
			if len(id1) != 16 {
				t.Errorf("expected 16-char hex ID, got %s", id1)
			}
		})
	}
}

func TestGenerateIDUniqueness(t *testing.T) {
	// Same IP across different targets should produce different IDs.
	id1 := GenerateID("ip", "targetA", "1.1.1.1")
	id2 := GenerateID("ip", "targetB", "1.1.1.1")
	if id1 == id2 {
		t.Error("cross-target IP IDs should differ, but got same")
	}
	// Same port across targets should differ.
	p1 := GenerateID("port", "targetA", "1.1.1.1", "80")
	p2 := GenerateID("port", "targetB", "1.1.1.1", "80")
	if p1 == p2 {
		t.Error("cross-target port IDs should differ, but got same")
	}
	// Same fingerprint name across targets should differ.
	f1 := GenerateID("fingerprint", "targetA", "ssh")
	f2 := GenerateID("fingerprint", "targetB", "ssh")
	if f1 == f2 {
		t.Error("cross-target fingerprint IDs should differ, but got same")
	}
}

func TestGenerateIDFormat(t *testing.T) {
	id := GenerateID("type", "a", "b")
	// Should be 16 lowercase hex characters.
	if len(id) != 16 {
		t.Errorf("expected 16 chars, got %d", len(id))
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex char in ID: %c", c)
		}
	}
}

func TestDedupeEvidenceKeepsHighestPriority(t *testing.T) {
	values := dedupeEvidence([]EvidenceRecord{
		{Type: "cve", Value: "CVE-2020-14882", Priority: 10},
		{Type: "cve", Value: "CVE-2020-14882", Priority: 90, Severity: "critical"},
		{Type: "template", Value: "CVE-2020-14882", Priority: 70},
	})
	if len(values) != 2 {
		t.Fatalf("expected 2 evidence records, got %#v", values)
	}
	for _, value := range values {
		if value.Type == "cve" && value.Priority != 90 {
			t.Fatalf("expected highest priority CVE evidence, got %#v", value)
		}
	}
}

func TestDedupeEvidenceKeepsLongerPathWhenPriorityTies(t *testing.T) {
	values := dedupeEvidence([]EvidenceRecord{
		{Type: "intel", Value: "CVE intel", Priority: 90, Path: []EvidencePathStep{{Type: "intel", Value: "CVE intel"}}},
		{Type: "intel", Value: "CVE intel", Priority: 90, Path: []EvidencePathStep{
			{Type: "fingerprint", Value: "weblogic"},
			{Relation: "identifies_product", Type: "product", Value: "Oracle WebLogic Server"},
			{Relation: "affected_by", Type: "cve", Value: "CVE-2020-14882"},
			{Relation: "has_intel", Type: "intel", Value: "CVE intel"},
		}},
	})
	if len(values) != 1 {
		t.Fatalf("expected one evidence record, got %#v", values)
	}
	if len(values[0].Path) != 4 {
		t.Fatalf("expected longer path to win, got %#v", values[0])
	}
}
