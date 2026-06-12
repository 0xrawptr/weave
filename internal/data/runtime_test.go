package data

import "testing"

func TestBlockedRuntimeQueuesDetectsQueuedWithoutWorker(t *testing.T) {
	groups := []WorkItemGroupSummary{
		{Key: "spray", Pending: 12, Queued: 12},
		{Key: "nuclei", Pending: 2, Running: 1, Queued: 2},
	}
	got := blockedRuntimeQueues(groups)
	if len(got) != 1 {
		t.Fatalf("len(blocked queues) = %d, want 1: %#v", len(got), got)
	}
	if got[0].Queue != "spray" || got[0].Reason != "eligible work is waiting for scheduler or capacity" {
		t.Fatalf("unexpected blocked queue: %#v", got[0])
	}
}

func TestRuntimePhaseBlockingReasonReportsStaleWork(t *testing.T) {
	open := []WorkItemGroupSummary{
		{Key: "portscan_chunk", Running: 1, StaleRunning: 1},
	}
	got := runtimePhaseBlockingReason(CampaignPhaseDiscovery, open, WorkItemProgressSummary{Total: 1})
	if got != "portscan_chunk has stale running work" {
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
	if len(got) != 2 || got[0].Key != "portscan_chunk" || got[1].Key != "spray_shard" {
		t.Fatalf("phase work = %#v, want portscan_chunk and spray_shard", got)
	}
}

func TestRuntimeExecutionPlanExplainsAllowedAndWaitingPhase(t *testing.T) {
	summary := WorkItemProgressSummary{ByType: []WorkItemGroupSummary{
		{Key: "spray_shard", Pending: 4, Queued: 4},
		{Key: "nuclei_group", Pending: 2, Queued: 2},
	}}
	plan := runtimeExecutionPlan(CampaignPhaseDiscovery, summary)
	byType := map[string]RuntimePlanItem{}
	for _, item := range plan {
		byType[item.Type] = item
	}
	if !byType["spray_shard"].Allowed || byType["spray_shard"].State != "queued" {
		t.Fatalf("spray plan = %#v, want allowed queued", byType["spray_shard"])
	}
	if byType["nuclei_group"].Allowed || byType["nuclei_group"].State != "waiting_phase" {
		t.Fatalf("nuclei plan = %#v, want waiting_phase", byType["nuclei_group"])
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
	got := blockedRuntimeQueuesForPlan(groups, plan)
	if len(got) != 1 || got[0].Queue != "spray" {
		t.Fatalf("blocked queues = %#v, want only spray", got)
	}
}
