package api

import (
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

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
