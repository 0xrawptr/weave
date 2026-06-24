package data

import (
	"testing"
	"time"
)

func TestRuntimeQueuesSeparateLiveStateFromCapacitySnapshot(t *testing.T) {
	groups := []WorkItemGroupSummary{
		{Key: "spray", Pending: 12, Queued: 12},
		{Key: "nuclei", Pending: 2, Running: 1, Queued: 2},
	}
	runtimeQueues := runtimeQueuesForPlan(groups, nil)
	if len(runtimeQueues) != 2 {
		t.Fatalf("len(runtime queues) = %d, want 2: %#v", len(runtimeQueues), runtimeQueues)
	}
	blocked := blockedRuntimeQueues(runtimeQueues)
	if len(blocked) != 1 {
		t.Fatalf("len(blocked queues) = %d, want 1: %#v", len(blocked), blocked)
	}
	if blocked[0].Queue != "spray" || blocked[0].Reason != "eligible work is waiting for scheduler admission" {
		t.Fatalf("unexpected blocked queue: %#v", blocked[0])
	}
}

func TestRuntimePhaseBlockingReasonReportsStaleWork(t *testing.T) {
	open := []WorkItemGroupSummary{
		{Key: "portscan_chunk", Running: 1, StalledRunning: 1},
	}
	got := runtimePhaseBlockingReason(CampaignPhaseDiscovery, open, WorkItemProgressSummary{Total: 1})
	if got != "portscan_chunk has running work without a valid progress heartbeat" {
		t.Fatalf("blocking reason = %q", got)
	}
}

func TestRuntimeETAConfidence(t *testing.T) {
	none := runtimeETA(WorkItemProgressSummary{
		Overall: WorkItemGroupSummary{Queued: 5},
	})
	if none.Confidence != "none" {
		t.Fatalf("confidence = %q, want none", none.Confidence)
	}
	medium := runtimeETA(WorkItemProgressSummary{
		ETASeconds:       120,
		ThroughputPerMin: 3,
		Overall:          WorkItemGroupSummary{Queued: 5},
	})
	if medium.Confidence != "medium" {
		t.Fatalf("confidence = %q, want medium", medium.Confidence)
	}
	low := runtimeETA(WorkItemProgressSummary{
		ETASeconds: 120,
		Overall:    WorkItemGroupSummary{Queued: 5, Running: 1, AvgDurationMs: 1000},
	})
	if low.Confidence != "low" {
		t.Fatalf("confidence = %q, want low", low.Confidence)
	}
}

func TestOpenRuntimePhaseWorkUsesCurrentPhaseTypes(t *testing.T) {
	summary := WorkItemProgressSummary{ByType: []WorkItemGroupSummary{
		{Key: "portscan_chunk", Pending: 1, Queued: 1},
		{Key: "spray_shard", Pending: 10, Queued: 10},
	}}
	got := openRuntimePhaseWork(CampaignPhaseDiscovery, summary)
	if len(got) != 1 || got[0].Key != "portscan_chunk" {
		t.Fatalf("phase work = %#v, want only portscan_chunk", got)
	}
}

func TestRuntimeExecutionPlanExplainsAllowedAndWaitingPhase(t *testing.T) {
	summary := WorkItemProgressSummary{ByType: []WorkItemGroupSummary{
		{Key: "spray_shard", Pending: 4, Queued: 4},
		{Key: "nuclei_group", Pending: 2, Queued: 2},
	}}
	plan := runtimeExecutionPlan(CampaignPhaseVerification, summary)
	byType := map[string]RuntimePlanItem{}
	for _, item := range plan {
		byType[item.Type] = item
	}
	if !byType["spray_shard"].Allowed || byType["spray_shard"].State != "queued" {
		t.Fatalf("spray plan = %#v, want allowed queued", byType["spray_shard"])
	}
	if !byType["nuclei_group"].Allowed || byType["nuclei_group"].State != "queued" {
		t.Fatalf("nuclei plan = %#v, want allowed queued", byType["nuclei_group"])
	}
}

func TestRuntimeWithoutSprayShardHasNoPendingSprayQueue(t *testing.T) {
	summary := WorkItemProgressSummary{
		Total: 1,
		ByType: []WorkItemGroupSummary{
			{Key: "portscan_chunk", Total: 1, Completed: 1, Done: 1, ProgressPercent: 100},
		},
		ByQueue: []WorkItemGroupSummary{
			{Key: "portscan", Total: 1, Completed: 1, Done: 1, ProgressPercent: 100},
		},
	}

	plan := runtimeExecutionPlan(CampaignPhaseExpansion, summary)
	for _, item := range plan {
		if item.Type == WorkItemTypeSprayShard && (item.Pending > 0 || item.Running > 0 || item.RetryWaiting > 0 || item.Paused > 0) {
			t.Fatalf("spray runtime plan has open work: %#v", item)
		}
	}

	queues := runtimeQueuesForPlan(summary.ByQueue, plan)
	for _, queue := range queues {
		if queue.Queue == "spray" {
			t.Fatalf("runtime queues contain pending spray without spray_shard work: %#v", queues)
		}
	}
	if blocked := blockedRuntimeQueues(queues); len(blocked) != 0 {
		t.Fatalf("blocked queues = %#v, want none", blocked)
	}
}

func TestBlockedRuntimeQueuesIgnoresQueuesWaitingForPhase(t *testing.T) {
	groups := []WorkItemGroupSummary{
		{Key: "spray", Pending: 4, Queued: 4},
		{Key: "nuclei", Pending: 2, Queued: 2},
	}
	plan := []RuntimePlanItem{
		{Queue: "spray", Allowed: true},
		{Queue: "nuclei", Allowed: false},
	}
	got := blockedRuntimeQueues(runtimeQueuesForPlan(groups, plan))
	if len(got) != 1 || got[0].Queue != "spray" {
		t.Fatalf("blocked queues = %#v, want only spray", got)
	}
}

func TestRuntimeCurrentBottleneckPrefersStalledWork(t *testing.T) {
	view := CampaignRuntimeView{
		ExecutionPlan: []RuntimePlanItem{
			{Type: "spray_shard", Queue: "spray", Artifact: "spray", Pending: 20, StalledRunning: 1, LastError: "lease expired"},
			{Type: "nuclei_group", Queue: "nuclei", Artifact: "nuclei", Failed: 2, LastError: "template error"},
		},
	}
	got := runtimeCurrentBottleneck(view)
	if got == nil || got.Kind != "stalled_work" || got.Type != "spray_shard" || got.LastError != "lease expired" {
		t.Fatalf("bottleneck = %#v, want stalled spray work", got)
	}
}

func TestRuntimeCurrentBottleneckFallsBackToBlockedQueue(t *testing.T) {
	view := CampaignRuntimeView{
		BlockedQueues: []QueueRuntimeState{
			{Queue: "spray", Pending: 12, Reason: "eligible work is waiting for scheduler admission"},
		},
	}
	got := runtimeCurrentBottleneck(view)
	if got == nil || got.Kind != "queue" || got.Queue != "spray" {
		t.Fatalf("bottleneck = %#v, want blocked spray queue", got)
	}
}

func TestRuntimeRunningWorkIsVisibleAndBlocking(t *testing.T) {
	summary := WorkItemProgressSummary{ByType: []WorkItemGroupSummary{
		{Key: "spray_shard", Running: 3},
	}}
	plan := runtimeExecutionPlan(CampaignPhaseSteady, summary)
	byType := map[string]RuntimePlanItem{}
	for _, item := range plan {
		byType[item.Type] = item
	}
	if byType["spray_shard"].State != "running" || byType["spray_shard"].Running != 3 {
		t.Fatalf("spray plan = %#v, want running state", byType["spray_shard"])
	}
	view := CampaignRuntimeView{ExecutionPlan: plan}
	if got := runtimeCurrentBottleneck(view); got == nil || got.Kind != "phase_work" || got.Type != "spray_shard" {
		t.Fatalf("bottleneck = %#v, want active spray phase work", got)
	}
	queues := runtimeQueuesForPlan([]WorkItemGroupSummary{{Key: "spray", Running: 3}}, plan)
	if len(queues) != 1 || queues[0].Running != 3 || queues[0].Reason != "actively executing" {
		t.Fatalf("queues = %#v, want visible tail queue", queues)
	}
}

func TestNoProgressRunningUsesDurationThreshold(t *testing.T) {
	stalled := WorkItemGroupSummary{
		Running:                1,
		OldestRunningStartedAt: time.Now().Add(-20 * time.Minute).Format(time.RFC3339),
		AvgDurationMs:          1000,
	}
	if got := noProgressRunning(stalled); got != 1 {
		t.Fatalf("noProgressRunning(stalled) = %d, want 1", got)
	}

	recent := WorkItemGroupSummary{
		Running:                1,
		OldestRunningStartedAt: time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
		AvgDurationMs:          1000,
	}
	if got := noProgressRunning(recent); got != 0 {
		t.Fatalf("noProgressRunning(recent) = %d, want 0", got)
	}
}

func TestRuntimeWarningsReportNoProgressRunning(t *testing.T) {
	view := CampaignRuntimeView{
		ExecutionPlan: []RuntimePlanItem{{NoProgressRunning: 1}},
	}
	got := runtimeWarnings(view)
	if !containsString(got, "running work has no valid progress heartbeat") {
		t.Fatalf("warnings = %#v, want no-progress warning", got)
	}
}

func TestRuntimeWarningsDeduplicateProgressHeartbeatWarning(t *testing.T) {
	view := CampaignRuntimeView{
		Summary:       WorkItemProgressSummary{Overall: WorkItemGroupSummary{StalledRunning: 1}},
		ExecutionPlan: []RuntimePlanItem{{NoProgressRunning: 1}},
	}
	got := runtimeWarnings(view)
	count := 0
	for _, warning := range got {
		if warning == "running work has no valid progress heartbeat" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("warnings = %#v, want one progress heartbeat warning", got)
	}
}

func TestProblemRuntimeArtifactsFiltersHealthyArtifacts(t *testing.T) {
	got := problemRuntimeArtifacts([]ArtifactRuntimeHealth{
		{Artifact: "gogo", StatRecords: 10, WorkItemRuns: 10, Reason: "healthy"},
		{Artifact: "spray", StatRecords: 5, WorkItemRuns: 5, Errors: 1, ErrorRatePercent: 20, Reason: "errors observed"},
	})
	if len(got) != 1 || got[0].Artifact != "spray" {
		t.Fatalf("problem artifacts = %#v, want only spray", got)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
