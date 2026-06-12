package planner

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

// Action is a planner decision derived from current assets and enrichment.
type Action struct {
	ID         string                 `json:"id"`
	CampaignID string                 `json:"campaign_id,omitempty"`
	WorkflowID string                 `json:"workflow_id,omitempty"`
	Target     string                 `json:"target"`
	Artifact   string                 `json:"artifact"`
	Input      map[string]interface{} `json:"input"`
	Reason     string                 `json:"reason"`
	Status     string                 `json:"status"`
	Evidence   []Evidence             `json:"evidence,omitempty"`
	Risk       string                 `json:"risk,omitempty"`
	Cost       int                    `json:"cost,omitempty"`
	DedupKey   string                 `json:"dedup_key,omitempty"`
	Decision   Decision               `json:"decision"`
}

type Decision struct {
	Suppressed bool   `json:"suppressed"`
	Schedule   string `json:"schedule"` // now, batch
	Reason     string `json:"reason,omitempty"`
}

const (
	ScheduleNow   = "now"
	ScheduleBatch = "batch"
)

type Planner struct {
	repo *data.Repository
}

type State struct {
	Target        string
	CampaignID    string
	URLs          []string
	BaseURLs      []string
	SprayURLs     []string
	HighValueURLs []string
	TemplateIDs   []string
	Tags          []string
	Fingerprints  []string
	CVEs          []data.Asset
	Evidence      []data.EvidenceRecord
	Actions       []data.ActionRecord
}

type Evidence struct {
	Type       string             `json:"type"`
	Value      string             `json:"value"`
	Confidence float64            `json:"confidence,omitempty"`
	Severity   string             `json:"severity,omitempty"`
	Status     string             `json:"status,omitempty"`
	Path       []EvidencePathStep `json:"path,omitempty"`
}

type EvidencePathStep struct {
	Relation string `json:"relation,omitempty"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

type DAGPlan struct {
	Target     string        `json:"target"`
	CampaignID string        `json:"campaign_id,omitempty"`
	Nodes      []DAGPlanNode `json:"nodes"`
	Actions    []Action      `json:"actions,omitempty"`
}

type DAGPlanNode struct {
	ID         string            `json:"id"`
	Artifact   string            `json:"artifact"`
	Target     string            `json:"target"`
	CampaignID string            `json:"campaign_id,omitempty"`
	Input      map[string]any    `json:"input,omitempty"`
	DependsOn  []string          `json:"depends_on,omitempty"`
	RunIf      *ConditionRequest `json:"run_if,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Risk       string            `json:"risk,omitempty"`
	Cost       int               `json:"cost,omitempty"`
	DedupKey   string            `json:"dedup_key,omitempty"`
	Evidence   []Evidence        `json:"evidence,omitempty"`
	Decision   Decision          `json:"decision"`
}

func New(repo *data.Repository) *Planner {
	return &Planner{repo: repo}
}

// PlanForTarget converts the current asset graph into next-step scan actions.
// It intentionally returns recommendations; workflow execution can consume the
// same actions later without changing this decision logic.
func (p *Planner) PlanForTarget(ctx context.Context, target string) ([]Action, error) {
	return p.PlanForTargetInCampaign(ctx, target, "")
}

func (p *Planner) PlanForTargetInCampaign(ctx context.Context, target, campaignID string) ([]Action, error) {
	if p == nil || p.repo == nil {
		return nil, nil
	}

	urls, err := p.repo.GetWebURLsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	templateIDs, err := p.repo.GetTemplateIDsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	tags, err := p.repo.GetTagsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	fingerprints, err := p.repo.GetFingerprintsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	discoveredURLs, err := p.repo.GetDiscoveredURLsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	var sprayURLs []string
	var highValueURLs []string
	for _, asset := range discoveredURLs {
		sprayURLs = append(sprayURLs, asset.Value)
		if isHighValueURLAsset(asset) {
			highValueURLs = append(highValueURLs, asset.Value)
		}
	}
	cves, err := p.repo.GetCVEAssetsInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	records, err := p.repo.GetActionRecordsFiltered(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	if campaignID != "" {
		workItems, err := p.repo.GetWorkItems(ctx, campaignID, "", "", "", "", target, 100000, 0)
		if err != nil {
			return nil, err
		}
		records = append(records, actionRecordsFromWorkItems(workItems)...)
	}
	evidence, err := p.repo.GetKnowledgeEvidenceInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}

	return PlanFromState(State{
		Target:        target,
		CampaignID:    campaignID,
		URLs:          append(append([]string{}, urls...), sprayURLs...),
		BaseURLs:      urls,
		SprayURLs:     sprayURLs,
		HighValueURLs: highValueURLs,
		TemplateIDs:   templateIDs,
		Tags:          tags,
		Fingerprints:  fingerprints,
		CVEs:          cves,
		Evidence:      evidence,
		Actions:       records,
	}), nil
}

func (p *Planner) PlanDAGForTarget(ctx context.Context, target, campaignID string) (*DAGPlan, error) {
	actions, err := p.PlanForTargetInCampaign(ctx, target, campaignID)
	if err != nil {
		return nil, err
	}
	plan := PlanDAGFromActions(target, campaignID, actions)
	return &plan, nil
}

func PlanFromState(state State) []Action {
	targets := unique(state.URLs)
	httpURLs := uniqueHTTP(state.URLs)
	baseURLs := uniqueHTTP(state.BaseURLs)
	if len(baseURLs) == 0 {
		baseURLs = serviceBaseURLs(httpURLs)
	}
	sprayURLs := uniqueHTTP(state.SprayURLs)
	highValueURLs := uniqueHTTP(state.HighValueURLs)
	if len(targets) == 0 {
		targets = unique(append(append([]string{}, baseURLs...), sprayURLs...))
	}
	if len(httpURLs) == 0 {
		httpURLs = uniqueHTTP(append(append([]string{}, baseURLs...), sprayURLs...))
	}
	templateIDs := unique(state.TemplateIDs)
	tags := unique(state.Tags)
	fingerprints := unique(state.Fingerprints)

	var actions []Action
	if len(targets) == 0 {
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "gogo"),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "gogo",
			Input:      map[string]interface{}{"ip": state.Target, "ports": "top3"},
			Reason:     "no web service URLs are available yet",
			Status:     "candidate",
			Evidence:   []Evidence{{Type: "target", Value: state.Target}},
			Risk:       "low",
			Cost:       40,
			DedupKey:   actionDedupKey(state.Target, "gogo", "top3"),
		})
		return finalizeActions(actions, state.Actions)
	}

	fingerTargets := httpURLs
	if len(fingerprints) > 0 && len(sprayURLs) > 0 {
		fingerTargets = sprayURLs
	}
	fingerTargets = withoutCoveredValues(fingerTargets, state.Actions, "fingers", "urls")
	if len(fingerTargets) > 0 && (len(fingerprints) == 0 || len(sprayURLs) > 0) {
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "fingers", joinKey(fingerTargets)),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "fingers",
			Input:      map[string]interface{}{"mode": "http_match", "urls": fingerTargets},
			Reason:     fingersReason(len(fingerprints), len(sprayURLs)),
			Status:     "candidate",
			Evidence:   stringEvidence("url", fingerTargets),
			Risk:       "low",
			Cost:       25,
			DedupKey:   actionDedupKey(state.Target, "fingers", joinKey(fingerTargets)),
		})
	}

	sprayBaseURLs := withoutCoveredValues(baseURLs, state.Actions, "spray", "base_urls")
	for _, baseURL := range sprayBaseURLs {
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "spray", "full", baseURL),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "spray",
			Input:      map[string]interface{}{"base_urls": []string{baseURL}, "wordlist_mode": "full"},
			Reason:     "expand attack surface with full path discovery",
			Status:     "candidate",
			Evidence:   stringEvidence("url", []string{baseURL}),
			Risk:       "medium",
			Cost:       45,
			DedupKey:   actionDedupKey(state.Target, "spray", "full", baseURL),
		})
	}

	nucleiTargets := verificationTargets(targets, highValueURLs)

	if len(templateIDs) > 0 {
		cveEvidence := append(cveEvidence(state.CVEs), graphEvidence(state.Evidence)...)
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "nuclei", "ids", joinKey(templateIDs)),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "nuclei",
			Input:      map[string]interface{}{"targets": nucleiTargets, "ids": templateIDs},
			Reason:     "enrichment produced precise nuclei template IDs",
			Status:     "candidate",
			Evidence:   append(stringEvidence("template", templateIDs), cveEvidence...),
			Risk:       "medium",
			Cost:       35,
			DedupKey:   actionDedupKey(state.Target, "nuclei", "ids", joinKey(templateIDs)),
		})
	} else if len(tags) > 0 || len(fingerprints) > 0 {
		filterTags := tags
		if len(filterTags) == 0 {
			filterTags = fingerprints
		}
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "nuclei", "tags", joinKey(filterTags)),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "nuclei",
			Input:      map[string]interface{}{"targets": nucleiTargets, "tags": filterTags},
			Reason:     "no precise template IDs exist; using tags/fingerprints as a broader filter",
			Status:     "candidate",
			Evidence:   append(append(stringEvidence("tag", tags), stringEvidence("fingerprint", fingerprints)...), graphEvidence(state.Evidence)...),
			Risk:       "medium",
			Cost:       60,
			DedupKey:   actionDedupKey(state.Target, "nuclei", "tags", joinKey(filterTags)),
		})
	} else if len(highValueURLs) > 0 {
		fallbackTags := []string{"exposure", "panel", "misconfig", "default-login", "discovery"}
		actions = append(actions, Action{
			ID:         data.GenerateID("action", state.Target, "nuclei", "high-value-url-fallback", joinKey(highValueURLs)),
			CampaignID: state.CampaignID,
			Target:     state.Target,
			Artifact:   "nuclei",
			Input:      map[string]interface{}{"targets": highValueURLs, "tags": fallbackTags},
			Reason:     "spray discovered high-value URLs but no precise template evidence exists; using lightweight nuclei tag fallback",
			Status:     "candidate",
			Evidence:   stringEvidence("url", highValueURLs),
			Risk:       "medium",
			Cost:       55,
			DedupKey:   actionDedupKey(state.Target, "nuclei", "high-value-url-fallback", joinKey(highValueURLs)),
		})
	}

	return finalizeActions(actions, state.Actions)
}

func finalizeActions(actions []Action, records []data.ActionRecord) []Action {
	for i := range actions {
		applyDecision(&actions[i])
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Decision.Schedule == actions[j].Decision.Schedule {
			if dagStage(actions[i].Artifact) == dagStage(actions[j].Artifact) {
				return actions[i].Artifact < actions[j].Artifact
			}
			return dagStage(actions[i].Artifact) < dagStage(actions[j].Artifact)
		}
		return scheduleRank(actions[i].Decision.Schedule) > scheduleRank(actions[j].Decision.Schedule)
	})
	return filterBlockedActions(actions, records)
}

func PlanDAGFromActions(target, campaignID string, actions []Action) DAGPlan {
	actions = append([]Action{}, actions...)
	for i := range actions {
		applyDecision(&actions[i])
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if dagStage(actions[i].Artifact) == dagStage(actions[j].Artifact) {
			if actions[i].Decision.Schedule == actions[j].Decision.Schedule {
				return actions[i].ID < actions[j].ID
			}
			return scheduleRank(actions[i].Decision.Schedule) > scheduleRank(actions[j].Decision.Schedule)
		}
		return dagStage(actions[i].Artifact) < dagStage(actions[j].Artifact)
	})

	byArtifact := make(map[string][]string)
	nodes := make([]DAGPlanNode, 0, len(actions))
	for _, action := range actions {
		if action.CampaignID == "" {
			action.CampaignID = campaignID
		}
		nodeID := actionNodeID(action)
		node := DAGPlanNode{
			ID:         nodeID,
			Artifact:   action.Artifact,
			Target:     action.Target,
			CampaignID: action.CampaignID,
			Input:      action.Input,
			DependsOn:  actionDependsOn(action, byArtifact),
			RunIf:      actionRunIf(action),
			Reason:     action.Reason,
			Risk:       action.Risk,
			Cost:       action.Cost,
			DedupKey:   action.DedupKey,
			Evidence:   action.Evidence,
			Decision:   action.Decision,
		}
		nodes = append(nodes, node)
		byArtifact[action.Artifact] = append(byArtifact[action.Artifact], nodeID)
	}
	return DAGPlan{
		Target:     target,
		CampaignID: campaignID,
		Nodes:      nodes,
		Actions:    actions,
	}
}

func dagStage(artifact string) int {
	switch artifact {
	case "gogo":
		return 10
	case "fingers":
		return 20
	case "spray":
		return 30
	case "nuclei", "neutron":
		return 40
	default:
		return 50
	}
}

func actionNodeID(action Action) string {
	parts := []string{"node", action.Artifact}
	if action.DedupKey != "" {
		parts = append(parts, action.DedupKey)
	} else if action.ID != "" {
		parts = append(parts, action.ID)
	}
	return data.GenerateID(parts...)
}

func actionDependsOn(action Action, byArtifact map[string][]string) []string {
	var deps []string
	add := func(ids []string) {
		for _, id := range ids {
			if id != "" {
				deps = append(deps, id)
			}
		}
	}
	switch action.Artifact {
	case "fingers":
		add(byArtifact["gogo"])
	case "spray":
		if len(byArtifact["fingers"]) > 0 {
			add(byArtifact["fingers"])
		} else {
			add(byArtifact["gogo"])
		}
	case "nuclei", "neutron":
		add(byArtifact["fingers"])
		add(byArtifact["spray"])
	}
	return unique(deps)
}

func actionRunIf(action Action) *ConditionRequest {
	switch action.Artifact {
	case "fingers":
		return &ConditionRequest{
			Target:     action.Target,
			CampaignID: action.CampaignID,
			Any: []AssetCondition{
				{Type: "service", MinCount: 1},
				{Type: "url", MinCount: 1},
			},
		}
	case "spray":
		return nil
	case "nuclei", "neutron":
		return &ConditionRequest{
			Target:     action.Target,
			CampaignID: action.CampaignID,
			Any: []AssetCondition{
				{Type: "template", MinCount: 1},
				{Type: "tag", MinCount: 1},
				{Type: "fingerprint", MinCount: 1},
				{Type: "cve", MinCount: 1},
				{Type: "url", Source: "spray", Status: "candidate", MinCount: 1},
				{Type: "url", Source: "spray", Status: "observed", MinCount: 1},
				{Type: "url", Source: "spray", Status: "interesting", MinCount: 1},
			},
		}
	default:
		return nil
	}
}

func (a Action) PersistInput() map[string]interface{} {
	out := make(map[string]interface{}, len(a.Input)+1)
	for key, value := range a.Input {
		out[key] = value
	}
	out["_planner"] = map[string]interface{}{
		"dedup_key": a.DedupKey,
		"decision":  a.Decision,
		"evidence":  a.Evidence,
	}
	return out
}

func applyDecision(action *Action) {
	if action == nil {
		return
	}
	if action.Decision.Schedule == "" && !action.Decision.Suppressed {
		action.Decision = decisionForAction(*action)
	}
}

func decisionForAction(action Action) Decision {
	if action.Artifact == "" {
		return Decision{Suppressed: true, Reason: "missing artifact"}
	}
	switch action.Artifact {
	case "nuclei", "neutron":
		if hasPreciseEvidence(action.Evidence) {
			return Decision{Schedule: ScheduleNow, Reason: "precise vulnerability evidence"}
		}
		if hasHighSeverityEvidence(action.Evidence) {
			return Decision{Schedule: ScheduleNow, Reason: "high severity evidence"}
		}
		return Decision{Schedule: ScheduleBatch, Reason: "verification can run in batch"}
	case "fingers":
		return Decision{Schedule: ScheduleBatch, Reason: "fingerprint enrichment"}
	case "gogo", "spray":
		return Decision{Schedule: ScheduleBatch, Reason: "surface discovery"}
	default:
		return Decision{Schedule: ScheduleBatch, Reason: "default batch schedule"}
	}
}

func scheduleRank(schedule string) int {
	switch schedule {
	case ScheduleNow:
		return 1
	case ScheduleBatch, "":
		return 0
	default:
		return 0
	}
}

func hasPreciseEvidence(evidence []Evidence) bool {
	for _, ev := range evidence {
		switch ev.Type {
		case "cve", "template", "intel":
			if strings.TrimSpace(ev.Value) != "" {
				return true
			}
		}
	}
	return false
}

func hasHighSeverityEvidence(evidence []Evidence) bool {
	for _, ev := range evidence {
		switch strings.ToLower(strings.TrimSpace(ev.Severity)) {
		case "critical", "high":
			return true
		}
	}
	return false
}

func isHighValueURLAsset(asset data.Asset) bool {
	switch asset.Status {
	case "candidate", "interesting", "confirmed":
		return true
	default:
		return false
	}
}

func filterBlockedActions(actions []Action, records []data.ActionRecord) []Action {
	if len(actions) == 0 || len(records) == 0 {
		return actions
	}
	blocked := make(map[string]bool, len(records))
	blockedDedup := make(map[string]bool, len(records))
	for _, record := range records {
		if blocksActionStatus(record.Status) {
			blocked[record.ID] = true
			if dedup := recordDedupKey(record); dedup != "" {
				blockedDedup[dedup] = true
			}
		}
	}
	if len(blocked) == 0 && len(blockedDedup) == 0 {
		return actions
	}
	filtered := make([]Action, 0, len(actions))
	for _, action := range actions {
		if !blocked[action.ID] && !blockedDedup[action.DedupKey] {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

func fingersReason(existingFingerprints, sprayURLs int) string {
	if existingFingerprints > 0 && sprayURLs > 0 {
		return "spray discovered new URLs that need fingerprinting"
	}
	return "web services exist but no fingerprints have been observed"
}

func verificationTargets(urls, highValueURLs []string) []string {
	highValueURLs = uniqueHTTP(highValueURLs)
	if len(highValueURLs) > 0 {
		return highValueURLs
	}
	return unique(urls)
}

func serviceBaseURLs(urls []string) []string {
	return uniqueHTTP(urls)
}

func withoutCoveredValues(values []string, records []data.ActionRecord, artifact, field string) []string {
	values = uniqueHTTP(values)
	if len(values) == 0 || len(records) == 0 {
		return values
	}
	covered := make(map[string]bool)
	for _, record := range records {
		if record.Artifact != artifact || !blocksActionStatus(record.Status) {
			continue
		}
		for _, value := range recordInputStrings(record, field) {
			covered[value] = true
		}
	}
	if len(covered) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !covered[value] {
			out = append(out, value)
		}
	}
	return out
}

func recordDedupKey(record data.ActionRecord) string {
	var input map[string]interface{}
	if len(record.Input) == 0 || json.Unmarshal(record.Input, &input) != nil {
		return ""
	}
	plannerMeta, ok := input["_planner"].(map[string]interface{})
	if !ok {
		return ""
	}
	dedup, _ := plannerMeta["dedup_key"].(string)
	return dedup
}

func recordInputStrings(record data.ActionRecord, field string) []string {
	var input map[string]interface{}
	if len(record.Input) == 0 || json.Unmarshal(record.Input, &input) != nil {
		return nil
	}
	values, ok := input[field].([]interface{})
	if !ok {
		if nested, nestedOK := input["input"].(map[string]interface{}); nestedOK {
			values, ok = nested[field].([]interface{})
		}
	}
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func blocksActionStatus(status string) bool {
	switch status {
	case data.WorkItemStatusPending, data.WorkItemStatusStarting, data.WorkItemStatusRunning, data.WorkItemStatusCompleted, data.WorkItemStatusRetryWaiting, data.WorkItemStatusPaused:
		return true
	default:
		return false
	}
}

func actionRecordsFromWorkItems(items []data.WorkItem) []data.ActionRecord {
	records := make([]data.ActionRecord, 0, len(items))
	for _, item := range items {
		record, ok := actionRecordFromWorkItem(item)
		if ok {
			records = append(records, record)
		}
	}
	return records
}

func actionRecordFromWorkItem(item data.WorkItem) (data.ActionRecord, bool) {
	if !blocksActionStatus(item.Status) || item.Artifact == "" || len(item.Input) == 0 {
		return data.ActionRecord{}, false
	}
	var envelope struct {
		Input    map[string]interface{} `json:"input"`
		DedupKey string                 `json:"dedup_key"`
		Reason   string                 `json:"reason"`
	}
	if json.Unmarshal(item.Input, &envelope) != nil || len(envelope.Input) == 0 {
		return data.ActionRecord{}, false
	}
	input := copyMap(envelope.Input)
	if envelope.DedupKey != "" {
		plannerMeta, _ := input["_planner"].(map[string]interface{})
		if plannerMeta == nil {
			plannerMeta = map[string]interface{}{}
			input["_planner"] = plannerMeta
		}
		plannerMeta["dedup_key"] = envelope.DedupKey
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return data.ActionRecord{}, false
	}
	return data.ActionRecord{
		ID:         item.ID,
		CampaignID: item.CampaignID,
		Target:     item.Target,
		Artifact:   item.Artifact,
		Input:      raw,
		Schedule:   item.Schedule,
		Reason:     envelope.Reason,
		Status:     item.Status,
		Attempts:   item.Attempts,
		WorkflowID: item.WorkflowID,
		Error:      item.Error,
		CreatedAt:  item.CreatedAt,
		UpdatedAt:  item.UpdatedAt,
		StartedAt:  item.StartedAt,
	}, true
}

func copyMap(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringEvidence(kind string, values []string) []Evidence {
	values = unique(values)
	out := make([]Evidence, 0, len(values))
	for _, value := range values {
		out = append(out, Evidence{Type: kind, Value: value, Status: "observed"})
	}
	return out
}

func cveEvidence(assets []data.Asset) []Evidence {
	assets = uniqueCVEAssets(assets)
	out := make([]Evidence, 0, len(assets))
	for _, asset := range assets {
		out = append(out, Evidence{
			Type:       "cve",
			Value:      asset.Value,
			Confidence: asset.Confidence,
			Severity:   asset.Severity,
			Status:     asset.Status,
		})
	}
	return out
}

func graphEvidence(records []data.EvidenceRecord) []Evidence {
	records = uniqueEvidenceRecords(records)
	out := make([]Evidence, 0, len(records))
	for _, record := range records {
		out = append(out, Evidence{
			Type:       record.Type,
			Value:      record.Value,
			Confidence: record.Confidence,
			Severity:   record.Severity,
			Status:     record.Status,
			Path:       evidencePathSteps(record.Path),
		})
	}
	return out
}

func evidencePathSteps(path []data.EvidencePathStep) []EvidencePathStep {
	if len(path) == 0 {
		return nil
	}
	out := make([]EvidencePathStep, 0, len(path))
	for _, step := range path {
		if step.Type == "" || step.Value == "" {
			continue
		}
		out = append(out, EvidencePathStep{
			Relation: step.Relation,
			Type:     step.Type,
			Value:    step.Value,
		})
	}
	return out
}

func uniqueEvidenceRecords(records []data.EvidenceRecord) []data.EvidenceRecord {
	seen := make(map[string]int, len(records))
	var out []data.EvidenceRecord
	for _, record := range records {
		if record.Type == "" || record.Value == "" {
			continue
		}
		key := record.Type + "|" + record.Value
		if i, ok := seen[key]; ok {
			if len(record.Path) > len(out[i].Path) {
				out[i] = record
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, record)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Value < out[j].Value
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func uniqueCVEAssets(assets []data.Asset) []data.Asset {
	seen := make(map[string]int, len(assets))
	var out []data.Asset
	for _, asset := range assets {
		if asset.Value == "" {
			continue
		}
		if i, ok := seen[asset.Value]; ok {
			if severityRank(asset.Severity) > severityRank(out[i].Severity) {
				out[i] = asset
			}
			continue
		}
		seen[asset.Value] = len(out)
		out = append(out, asset)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) == severityRank(out[j].Severity) {
			return out[i].Value < out[j].Value
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func actionDedupKey(parts ...string) string {
	return joinKey(parts)
}

func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueHTTP(values []string) []string {
	return unique(filterHTTP(values))
}

func filterHTTP(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			out = append(out, value)
		}
	}
	return out
}

func joinKey(values []string) string {
	values = unique(values)
	out := ""
	for _, value := range values {
		out += "|" + value
	}
	return out
}
