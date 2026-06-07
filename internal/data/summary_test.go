package data

import (
	"testing"
	"time"
)

func TestCompleteWorkItemGroupSummary(t *testing.T) {
	group := WorkItemGroupSummary{
		Total:         10,
		Pending:       3,
		Running:       2,
		Completed:     4,
		Failed:        1,
		AvgDurationMs: 2000,
	}

	completeWorkItemGroupSummary(&group, 15)

	if group.Queued != 3 {
		t.Fatalf("queued = %d, want 3", group.Queued)
	}
	if group.Done != 4 {
		t.Fatalf("done = %d, want 4", group.Done)
	}
	if group.Error != 1 {
		t.Fatalf("error = %d, want 1", group.Error)
	}
	if group.ProgressPercent != 50 {
		t.Fatalf("progress = %d, want 50", group.ProgressPercent)
	}
	if group.ThroughputPerMin != 1 {
		t.Fatalf("throughput = %d, want 1", group.ThroughputPerMin)
	}
	if group.ETASeconds != 300 {
		t.Fatalf("eta = %d, want 300", group.ETASeconds)
	}
}

func TestCompleteArtifactStatSummary(t *testing.T) {
	summary := ArtifactStatSummary{
		TotalRuns: 2,
		Requests:  100,
		Results:   25,
		Errors:    5,
	}
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	last := first.Add(5 * time.Minute)

	completeArtifactStatSummary(&summary, first, last)

	if summary.ErrorRatePercent != 5 {
		t.Fatalf("error rate = %d, want 5", summary.ErrorRatePercent)
	}
	if summary.ThroughputPerMin != 5 {
		t.Fatalf("throughput = %d, want 5", summary.ThroughputPerMin)
	}
}
