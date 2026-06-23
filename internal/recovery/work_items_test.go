package recovery

import (
	"context"
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

func TestMergeWorkItemBulkResultsDeduplicatesBatches(t *testing.T) {
	got := MergeWorkItemBulkResults(
		data.WorkItemBulkResult{
			Matched: 1,
			Updated: 1,
			Batches: []data.WorkItemBulkBatch{{CampaignID: "camp-1", BatchID: "batch-1"}},
		},
		data.WorkItemBulkResult{
			Matched: 2,
			Updated: 2,
			Batches: []data.WorkItemBulkBatch{
				{CampaignID: "camp-1", BatchID: "batch-1"},
				{CampaignID: "camp-1", BatchID: "batch-2"},
			},
		},
	)
	if got.Matched != 3 || got.Updated != 3 {
		t.Fatalf("counts = (%d,%d), want (3,3)", got.Matched, got.Updated)
	}
	if len(got.Batches) != 2 {
		t.Fatalf("batches = %#v, want 2 unique batches", got.Batches)
	}
}

func TestRecoverExpiredRunningOrphansSkipsWithoutTemporal(t *testing.T) {
	result, status, err := RecoverExpiredRunningOrphans(context.Background(), &data.Repository{}, nil, data.WorkItemFilter{}, 100, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Updated != 0 || status != ExpiredRunningSkippedTemporalUnavailable {
		t.Fatalf("result=%#v status=%q, want skipped temporal unavailable", result, status)
	}
}
