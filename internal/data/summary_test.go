package data

import (
	"testing"
	"time"
)

func TestCompleteWorkItemGroupSummary(t *testing.T) {
	group := WorkItemGroupSummary{
		Total:         11,
		Pending:       3,
		Starting:      1,
		Running:       2,
		Completed:     4,
		Failed:        1,
		AvgDurationMs: 2000,
	}

	completeWorkItemGroupSummary(&group, 15)

	if group.Queued != 4 {
		t.Fatalf("queued = %d, want 4", group.Queued)
	}
	if group.Done != 4 {
		t.Fatalf("done = %d, want 4", group.Done)
	}
	if group.Error != 1 {
		t.Fatalf("error = %d, want 1", group.Error)
	}
	if group.ProgressPercent != 45 {
		t.Fatalf("progress = %d, want 45", group.ProgressPercent)
	}
	if group.ThroughputPerMin != 1 {
		t.Fatalf("throughput = %d, want 1", group.ThroughputPerMin)
	}
	if group.ETASeconds != 360 {
		t.Fatalf("eta = %d, want 360", group.ETASeconds)
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
		t.Fatalf("error rate = %f, want 5", summary.ErrorRatePercent)
	}
	if summary.ErrorScope != "request" {
		t.Fatalf("error scope = %q, want request", summary.ErrorScope)
	}
	if summary.RequestErrorRatePercent != 5 {
		t.Fatalf("request error rate = %f, want 5", summary.RequestErrorRatePercent)
	}
	if summary.ThroughputPerMin != 5 {
		t.Fatalf("throughput = %d, want 5", summary.ThroughputPerMin)
	}
}

func TestCompleteArtifactStatSummaryKeepsSubPercentErrorRate(t *testing.T) {
	summary := ArtifactStatSummary{
		TotalRuns: 77,
		Requests:  109987,
		Results:   28,
		Errors:    979,
	}
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	last := first.Add(5 * time.Minute)

	completeArtifactStatSummary(&summary, first, last)

	if summary.ErrorRatePercent <= 0 || summary.ErrorRatePercent >= 1 {
		t.Fatalf("error rate = %f, want sub-percent non-zero", summary.ErrorRatePercent)
	}
	if summary.RequestErrorRatePercent != summary.ErrorRatePercent {
		t.Fatalf("request error rate = %f, want %f", summary.RequestErrorRatePercent, summary.ErrorRatePercent)
	}
}
