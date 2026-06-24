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

func TestRecoverWorkItemsSkipsExpiredLeasesWithoutTemporal(t *testing.T) {
	result, err := RecoverWorkItems(context.Background(), &data.Repository{}, nil, RecoveryPolicy{
		RecoverExpiredLeases: true,
		Limit:                100,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.BulkResult().Updated != 0 || result.ExpiredLeaseStatus != ExpiredLeaseSkippedTemporalUnavailable {
		t.Fatalf("result=%#v, want skipped temporal unavailable", result)
	}
}

func TestRecoverWorkItemsReturnsEmptyWithoutRepo(t *testing.T) {
	result, err := RecoverWorkItems(context.Background(), nil, nil, RecoveryPolicy{
		RecoverFailures:      true,
		RecoverExpiredLeases: true,
		RequeueRetryWaiting:  true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bulk := result.BulkResult(); bulk.Updated != 0 || len(result.Batches) != 0 {
		t.Fatalf("result = %#v bulk=%#v, want empty", result, bulk)
	}
}

func TestRecoveryResultBulkResultMergesAllSources(t *testing.T) {
	result := RecoveryResult{
		RecoveredFailures:      data.WorkItemBulkResult{Matched: 1, Updated: 1, Batches: []data.WorkItemBulkBatch{{CampaignID: "c1", BatchID: "b1"}}},
		RecoveredExpiredLeases: data.WorkItemBulkResult{Matched: 2, Updated: 2, Batches: []data.WorkItemBulkBatch{{CampaignID: "c1", BatchID: "b1"}}},
		RequeuedRetries:        data.WorkItemBulkResult{Matched: 3, Updated: 3, Batches: []data.WorkItemBulkBatch{{CampaignID: "c1", BatchID: "b2"}}},
	}
	bulk := result.BulkResult()
	if bulk.Matched != 6 || bulk.Updated != 6 || len(bulk.Batches) != 2 {
		t.Fatalf("bulk = %#v, want merged counts and batches", bulk)
	}
}
