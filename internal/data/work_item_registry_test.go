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
	def, ok := WorkItemDefinitionForArtifact("nuclei")
	if !ok || def.Type != WorkItemTypeNucleiGroup {
		t.Fatalf("nuclei type = %q, %v; want %q, true", def.Type, ok, WorkItemTypeNucleiGroup)
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

func TestActionWorkItemDefinitionPolicies(t *testing.T) {
	spray, ok := WorkItemDefinitionForArtifact("spray")
	if !ok {
		t.Fatalf("missing spray definition")
	}
	if !spray.ReplanAfter {
		t.Fatalf("spray should trigger follow-up planning")
	}
	if len(spray.DependsOn) != 2 || spray.DependsOn[0] != "fingers" || spray.DependsOn[1] != "gogo" {
		t.Fatalf("spray dependencies = %#v", spray.DependsOn)
	}
	if spray.DefaultReason != "surface discovery" {
		t.Fatalf("spray default reason = %q", spray.DefaultReason)
	}
	nuclei, ok := WorkItemDefinitionForArtifact("nuclei")
	if !ok {
		t.Fatalf("missing nuclei definition")
	}
	if nuclei.ReplanAfter {
		t.Fatalf("nuclei should not trigger follow-up planning")
	}
	if len(nuclei.DependsOn) != 2 || nuclei.DependsOn[0] != "fingers" || nuclei.DependsOn[1] != "spray" {
		t.Fatalf("nuclei dependencies = %#v", nuclei.DependsOn)
	}
}
