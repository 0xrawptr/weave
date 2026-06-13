package data

import "testing"

func TestDecideSchedulerCapacityIncreasesHealthyBacklog(t *testing.T) {
	policy := SchedulerCapacityPolicy{Queue: "spray", Artifact: "spray", Min: 1, Initial: 3, Max: 6, SlowMs: 120_000, ErrorLimit: 25}
	got := decideSchedulerCapacity(
		SchedulerCapacityUpdateRequest{CampaignID: "c1", BatchID: "b1"},
		policy,
		SchedulerCapacity{EffectiveCapacity: 3},
		WorkItemGroupSummary{Pending: 20, Running: 3},
		ArtifactStatSummary{},
	)
	if got.EffectiveCapacity != 4 || got.LastDecision != "increase" {
		t.Fatalf("capacity = %#v, want increase to 4", got)
	}
}

func TestDecideSchedulerCapacityHalvesOnStaleRunning(t *testing.T) {
	policy := SchedulerCapacityPolicy{Queue: "portscan", Artifact: "gogo", Min: 1, Initial: 4, Max: 8, SlowMs: 180_000, ErrorLimit: 30}
	got := decideSchedulerCapacity(
		SchedulerCapacityUpdateRequest{CampaignID: "c1", BatchID: "b1"},
		policy,
		SchedulerCapacity{EffectiveCapacity: 8},
		WorkItemGroupSummary{Pending: 20, Running: 8, StaleRunning: 1},
		ArtifactStatSummary{},
	)
	if got.EffectiveCapacity != 4 || got.LastDecision != "decrease" {
		t.Fatalf("capacity = %#v, want decrease to 4", got)
	}
}

func TestDecideSchedulerCapacityHalvesOnArtifactErrorRate(t *testing.T) {
	policy := SchedulerCapacityPolicy{Queue: "nuclei", Artifact: "nuclei", Min: 1, Initial: 2, Max: 6, SlowMs: 240_000, ErrorLimit: 30}
	got := decideSchedulerCapacity(
		SchedulerCapacityUpdateRequest{CampaignID: "c1", BatchID: "b1"},
		policy,
		SchedulerCapacity{EffectiveCapacity: 4},
		WorkItemGroupSummary{Pending: 20, Running: 4},
		ArtifactStatSummary{Requests: 100, Errors: 60},
	)
	if got.EffectiveCapacity != 2 || got.ErrorRatePercent != 60 || got.LastDecision != "decrease" {
		t.Fatalf("capacity = %#v, want error-rate decrease to 2", got)
	}
}
