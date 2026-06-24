package api

import (
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

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

func TestStatusFromWorkItemCountsTreatsRunningAsActive(t *testing.T) {
	counts := map[string]int{
		data.WorkItemStatusCompleted: 9,
		data.WorkItemStatusRunning:   1,
	}
	if got := statusFromWorkItemCounts(10, counts); got != "running" {
		t.Fatalf("status = %q, want running", got)
	}
}

func TestMergeWorkItemFilterFieldsOverridesNestedFilter(t *testing.T) {
	got := mergeWorkItemFilterFields(WorkItemFilterAPIFields{
		Status: "pending",
		Filter: data.WorkItemFilter{
			CampaignID: "campaign-1",
			Status:     "failed",
			Artifact:   "spray",
		},
	})
	if got.CampaignID != "campaign-1" || got.Artifact != "spray" {
		t.Fatalf("filter = %#v, want nested fields preserved", got)
	}
	if got.Status != "pending" {
		t.Fatalf("status = %q, want top-level override", got.Status)
	}
}
