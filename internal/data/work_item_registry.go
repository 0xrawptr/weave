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
}

var workItemDefinitions = []WorkItemDefinition{
	{Type: WorkItemTypeDNSPreflight, Queue: "dns", Artifact: "dns_preflight", RuntimeArtifact: "dnsx", PrimaryPhase: CampaignPhaseBootstrap, AllowedPhases: []string{CampaignPhaseBootstrap}},
	{Type: WorkItemTypePortscanChunk, Queue: "portscan", Artifact: "gogo", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery}},
	{Type: WorkItemTypePlannedDAGFollowUp, Queue: "planner", Artifact: "planned_dag", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery}, Planner: true},
	{Type: WorkItemTypeFingersAction, Queue: "http", Artifact: "fingers", PrimaryPhase: CampaignPhaseDiscovery, AllowedPhases: []string{CampaignPhaseDiscovery, CampaignPhaseExpansion}, Planner: true},
	{Type: WorkItemTypeSprayShard, Queue: "spray", Artifact: "spray", PrimaryPhase: CampaignPhaseExpansion, AllowedPhases: []string{CampaignPhaseDiscovery, CampaignPhaseExpansion, CampaignPhaseVerification}, Planner: true},
	{Type: WorkItemTypeNucleiGroup, Queue: "nuclei", Artifact: "nuclei", PrimaryPhase: CampaignPhaseVerification, AllowedPhases: []string{CampaignPhaseVerification}, Planner: true},
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
	switch NormalizeCampaignPhase(phase) {
	case CampaignPhaseBootstrap:
		return []string{WorkItemTypeDNSPreflight}, false
	case CampaignPhaseDiscovery:
		return []string{WorkItemTypePortscanChunk, WorkItemTypePlannedDAGFollowUp, WorkItemTypeFingersAction, WorkItemTypeSprayShard}, false
	case CampaignPhaseExpansion:
		return []string{WorkItemTypeSprayShard, WorkItemTypeFingersAction}, false
	case CampaignPhaseVerification:
		return []string{WorkItemTypeNucleiGroup, WorkItemTypeSprayShard}, false
	case CampaignPhaseSteady:
		return []string{WorkItemTypeDNSPreflight, WorkItemTypePortscanChunk, WorkItemTypePlannedDAGFollowUp, WorkItemTypeFingersAction, WorkItemTypeSprayShard, WorkItemTypeNucleiGroup}, true
	default:
		return WorkItemTypesForPhase(CampaignPhaseDiscovery)
	}
}
