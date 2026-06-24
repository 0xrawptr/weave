package data

const (
	WorkItemTypeDNSPreflight       = "dns_preflight"
	WorkItemTypePortscanChunk      = "portscan_chunk"
	WorkItemTypePlannedDAGFollowUp = "planned_dag_followup"
	WorkItemTypeFingersAction      = "fingers_action"
	WorkItemTypeSprayShard         = "spray_shard"
	WorkItemTypeNucleiGroup        = "nuclei_group"
)

type WorkItemDefinition struct {
	Type            string
	Queue           string
	Artifact        string
	RuntimeArtifact string
	PrimaryPhase    string
	AllowedPhases   []string
	Planner         bool
	Action          bool
}

var workItemDefinitions = []WorkItemDefinition{
	{Type: WorkItemTypeDNSPreflight, Queue: "dns", Artifact: "dns_preflight", RuntimeArtifact: "dnsx", PrimaryPhase: CampaignPhaseBootstrap, AllowedPhases: []string{CampaignPhaseBootstrap}},
	{Type: WorkItemTypePortscanChunk, Queue: "portscan", Artifact: "gogo", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery}},
	{Type: WorkItemTypePlannedDAGFollowUp, Queue: "planner", Artifact: "planned_dag", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery}, Planner: true},
	{Type: WorkItemTypeFingersAction, Queue: "http", Artifact: "fingers", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery, CampaignPhaseExpansion}, Planner: true, Action: true},
	{Type: WorkItemTypeSprayShard, Queue: "spray", Artifact: "spray", PrimaryPhase: CampaignPhaseExpansion, AllowedPhases: []string{CampaignPhaseDiscovery, CampaignPhaseExpansion, CampaignPhaseVerification}, Planner: true, Action: true},
	{Type: WorkItemTypeNucleiGroup, Queue: "nuclei", Artifact: "nuclei", PrimaryPhase: CampaignPhaseVerification, AllowedPhases: []string{CampaignPhaseVerification}, Planner: true, Action: true},
}

func WorkItemDefinitions() []WorkItemDefinition {
	out := make([]WorkItemDefinition, len(workItemDefinitions))
	copy(out, workItemDefinitions)
	return out
}

func WorkItemDefinitionForType(itemType string) (WorkItemDefinition, bool) {
	for _, def := range workItemDefinitions {
		if def.Type == itemType {
			return def, true
		}
	}
	return WorkItemDefinition{}, false
}

func WorkItemDefinitionForArtifact(artifact string) (WorkItemDefinition, bool) {
	for _, def := range workItemDefinitions {
		if def.Artifact == artifact {
			return def, true
		}
	}
	return WorkItemDefinition{}, false
}

func WorkItemTypeForArtifact(artifact string) (string, bool) {
	def, ok := WorkItemDefinitionForArtifact(artifact)
	if !ok {
		return "", false
	}
	return def.Type, true
}

func WorkItemQueueForType(itemType string) string {
	if def, ok := WorkItemDefinitionForType(itemType); ok {
		return def.Queue
	}
	return itemType
}

func WorkItemArtifactForType(itemType string) string {
	if def, ok := WorkItemDefinitionForType(itemType); ok {
		return def.Artifact
	}
	return itemType
}

func ActionWorkItemTypes() []string {
	out := make([]string, 0, len(workItemDefinitions))
	for _, def := range workItemDefinitions {
		if def.Action {
			out = append(out, def.Type)
		}
	}
	return out
}

func WorkItemTypeAllowedInPhase(phase, itemType string) bool {
	phase = NormalizeCampaignPhase(phase)
	if phase == CampaignPhaseSteady {
		_, ok := WorkItemDefinitionForType(itemType)
		return ok
	}
	def, ok := WorkItemDefinitionForType(itemType)
	if !ok {
		return false
	}
	for _, allowed := range def.AllowedPhases {
		if allowed == phase {
			return true
		}
	}
	return false
}

func WorkItemTypesForPhase(phase string) ([]string, bool) {
	phase = NormalizeCampaignPhase(phase)
	if phase == CampaignPhaseAuto {
		return WorkItemTypesForPhase(CampaignPhaseDiscovery)
	}
	if phase == CampaignPhaseSteady {
		out := make([]string, 0, len(workItemDefinitions))
		for _, def := range workItemDefinitions {
			out = append(out, def.Type)
		}
		return out, true
	}
	out := make([]string, 0, len(workItemDefinitions))
	seen := map[string]bool{}
	for _, def := range workItemDefinitions {
		if def.PrimaryPhase == phase {
			out = append(out, def.Type)
			seen[def.Type] = true
		}
	}
	for _, def := range workItemDefinitions {
		if seen[def.Type] || !WorkItemTypeAllowedInPhase(phase, def.Type) {
			continue
		}
		out = append(out, def.Type)
	}
	return out, false
}

func InferCampaignPhaseFromSummary(summary WorkItemProgressSummary) string {
	if hasOpenWorkItemType(summary, WorkItemTypeDNSPreflight) {
		return CampaignPhaseBootstrap
	}
	if hasOpenWorkItemType(summary, WorkItemTypePortscanChunk) ||
		hasOpenWorkItemType(summary, WorkItemTypePlannedDAGFollowUp) ||
		hasOpenWorkItemType(summary, WorkItemTypeFingersAction) {
		return CampaignPhaseDiscovery
	}
	if hasOpenWorkItemType(summary, WorkItemTypeNucleiGroup) {
		return CampaignPhaseVerification
	}
	if hasOpenWorkItemType(summary, WorkItemTypeSprayShard) {
		return CampaignPhaseExpansion
	}
	return CampaignPhaseSteady
}

func OpenWorkItemGroupsForPhase(phase string, summary WorkItemProgressSummary) []WorkItemGroupSummary {
	phase = NormalizeCampaignPhase(phase)
	out := make([]WorkItemGroupSummary, 0, len(summary.ByType))
	for _, group := range summary.ByType {
		if OpenWorkItemGroup(group) == 0 {
			continue
		}
		if phase == CampaignPhaseSteady || WorkItemTypeAllowedInPhase(phase, group.Key) {
			out = append(out, group)
		}
	}
	return out
}

func OpenWorkItemGroup(group WorkItemGroupSummary) int {
	return group.Pending + group.Running + group.RetryWaiting + group.Paused
}

func hasOpenWorkItemType(summary WorkItemProgressSummary, itemType string) bool {
	for _, group := range summary.ByType {
		if group.Key == itemType && OpenWorkItemGroup(group) > 0 {
			return true
		}
	}
	return false
}
