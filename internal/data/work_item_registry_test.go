package data

import "testing"

func TestWorkItemTypesForPhaseDerivedFromDefinitions(t *testing.T) {
	tests := []struct {
		phase string
		want  []string
		now   bool
	}{
		{phase: CampaignPhaseBootstrap, want: []string{WorkItemTypeDNSPreflight}},
		{phase: CampaignPhaseDiscovery, want: []string{WorkItemTypePortscanChunk, WorkItemTypePlannedDAGFollowUp, WorkItemTypeFingersAction, WorkItemTypeSprayShard}},
		{phase: CampaignPhaseExpansion, want: []string{WorkItemTypeSprayShard, WorkItemTypeFingersAction}},
		{phase: CampaignPhaseVerification, want: []string{WorkItemTypeNucleiGroup, WorkItemTypeSprayShard}},
		{phase: CampaignPhaseSteady, want: []string{WorkItemTypeDNSPreflight, WorkItemTypePortscanChunk, WorkItemTypePlannedDAGFollowUp, WorkItemTypeFingersAction, WorkItemTypeSprayShard, WorkItemTypeNucleiGroup}, now: true},
	}

	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			got, now := WorkItemTypesForPhase(tt.phase)
			if now != tt.now {
				t.Fatalf("now only = %v, want %v", now, tt.now)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("types = %#v, want %#v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("types = %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}

func TestWorkItemDefinitionLookups(t *testing.T) {
	if got := WorkItemQueueForType(WorkItemTypeSprayShard); got != "spray" {
		t.Fatalf("spray queue = %q, want spray", got)
	}
	if got := WorkItemArtifactForType(WorkItemTypePortscanChunk); got != "gogo" {
		t.Fatalf("portscan artifact = %q, want gogo", got)
	}
	itemType, ok := WorkItemTypeForArtifact("nuclei")
	if !ok || itemType != WorkItemTypeNucleiGroup {
		t.Fatalf("nuclei type = %q, %v; want %q, true", itemType, ok, WorkItemTypeNucleiGroup)
	}
}

func TestActionWorkItemTypesExcludePlannerFollowUp(t *testing.T) {
	got := ActionWorkItemTypes()
	want := []string{WorkItemTypeFingersAction, WorkItemTypeSprayShard, WorkItemTypeNucleiGroup}
	if len(got) != len(want) {
		t.Fatalf("action types = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("action types = %#v, want %#v", got, want)
		}
	}
}
