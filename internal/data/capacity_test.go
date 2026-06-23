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

func TestDecideSchedulerCapacityHalvesOnStalledRunning(t *testing.T) {
	policy := SchedulerCapacityPolicy{Queue: "portscan", Artifact: "gogo", Min: 1, Initial: 4, Max: 8, SlowMs: 180_000, ErrorLimit: 30}
	got := decideSchedulerCapacity(
		SchedulerCapacityUpdateRequest{CampaignID: "c1", BatchID: "b1"},
		policy,
		SchedulerCapacity{EffectiveCapacity: 8},
		WorkItemGroupSummary{Pending: 20, Running: 8, StalledRunning: 1},
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

func TestSchedulerCapacityPoliciesComeFromProfiles(t *testing.T) {
	policies := DefaultSchedulerCapacityPolicies()
	if len(policies) == 0 {
		t.Fatal("expected scheduler capacity policies")
	}
	byQueue := map[string]SchedulerCapacityPolicy{}
	for _, policy := range policies {
		byQueue[policy.Queue] = policy
	}
	spray := byQueue["spray"]
	if spray.Artifact != "spray" || spray.Initial != 3 || spray.Max != 12 {
		t.Fatalf("spray policy = %#v, want profile-derived scheduler policy", spray)
	}
	if _, ok := byQueue[""]; ok {
		t.Fatal("profiles without a scheduler queue must not become scheduler policies")
	}
}

func TestRuntimeCapacityProfilesSeparateSchedulerAndSDKScopes(t *testing.T) {
	profiles := RuntimeCapacityProfiles(map[string]int{"spray": 123})
	var spray RuntimeCapacityProfile
	var neutron RuntimeCapacityProfile
	for _, profile := range profiles {
		switch profile.Artifact {
		case "spray":
			spray = profile
		case "neutron":
			neutron = profile
		}
	}
	if spray.SchedulerScope != "scheduler_admission" || spray.SDKScope != "sdk_engine_bucket" {
		t.Fatalf("spray scopes = %#v, want explicit scheduler/sdk scopes", spray)
	}
	if spray.SDKConfiguredCapacity != 123 || spray.SDKDefaultCapacity != 300 {
		t.Fatalf("spray sdk capacities = %#v, want override plus default", spray)
	}
	if neutron.SchedulerScope != "none" || neutron.SDKDefaultCapacity != 30 {
		t.Fatalf("neutron profile = %#v, want sdk-only profile", neutron)
	}
}
