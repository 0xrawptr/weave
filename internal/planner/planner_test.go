package planner

import (
	"encoding/json"
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

func TestPlanFromStateStartsWithGogoWhenNoURLs(t *testing.T) {
	actions := PlanFromState(State{Target: "example.com"})
	if len(actions) != 1 {
		t.Fatalf("expected one action, got %#v", actions)
	}
	if actions[0].Artifact != "gogo" {
		t.Fatalf("expected gogo action, got %#v", actions[0])
	}
}

func TestPlanFromStateUsesPreciseNucleiIDs(t *testing.T) {
	actions := PlanFromState(State{
		Target:       "example.com",
		URLs:         []string{"https://example.com"},
		Fingerprints: []string{"weblogic"},
		TemplateIDs:  []string{"CVE-2020-14882"},
		CVEs:         []data.Asset{{Value: "CVE-2020-14882", Priority: 95}},
	})
	nuclei := findAction(actions, "nuclei")
	if nuclei == nil {
		t.Fatalf("missing nuclei action: %#v", actions)
	}
	if nuclei.Priority != 95 {
		t.Fatalf("expected cve priority to win, got %d", nuclei.Priority)
	}
	if nuclei.DedupKey == "" {
		t.Fatalf("expected dedup key")
	}
	if nuclei.Score <= 0 {
		t.Fatalf("expected positive score, got %d", nuclei.Score)
	}
	if !hasEvidence(nuclei.Evidence, "cve", "CVE-2020-14882") {
		t.Fatalf("expected CVE evidence, got %#v", nuclei.Evidence)
	}
	ids, ok := nuclei.Input["ids"].([]string)
	if !ok || len(ids) != 1 || ids[0] != "CVE-2020-14882" {
		t.Fatalf("expected precise IDs, got %#v", nuclei.Input)
	}
	if _, ok := nuclei.Input["_planner"]; ok {
		t.Fatalf("execution input should not contain planner metadata: %#v", nuclei.Input)
	}
	if _, ok := nuclei.PersistInput()["_planner"].(map[string]interface{}); !ok {
		t.Fatalf("expected planner metadata in persisted input, got %#v", nuclei.PersistInput())
	}
}

func TestPlanFromStateFallsBackToTags(t *testing.T) {
	actions := PlanFromState(State{
		Target:       "example.com",
		URLs:         []string{"https://example.com"},
		Fingerprints: []string{"nginx"},
		Tags:         []string{"nginx"},
	})
	nuclei := findAction(actions, "nuclei")
	if nuclei == nil {
		t.Fatalf("missing nuclei action: %#v", actions)
	}
	if _, ok := nuclei.Input["ids"]; ok {
		t.Fatalf("did not expect IDs fallback action: %#v", nuclei.Input)
	}
	tags, ok := nuclei.Input["tags"].([]string)
	if !ok || len(tags) != 1 || tags[0] != "nginx" {
		t.Fatalf("expected tag filter, got %#v", nuclei.Input)
	}
}

func TestPlanFromStatePlansFullSprayForHTTPBaseURLs(t *testing.T) {
	actions := PlanFromState(State{
		Target:   "example.com",
		BaseURLs: []string{"https://example.com", "tcp://example.com:5432"},
		URLs:     []string{"https://example.com", "tcp://example.com:5432"},
	})
	spray := findAction(actions, "spray")
	if spray == nil {
		t.Fatalf("missing spray action: %#v", actions)
	}
	if spray.Input["wordlist_mode"] != "full" {
		t.Fatalf("expected full spray mode, got %#v", spray.Input)
	}
	baseURLs, ok := spray.Input["base_urls"].([]string)
	if !ok || len(baseURLs) != 1 || baseURLs[0] != "https://example.com" {
		t.Fatalf("expected only HTTP base URLs, got %#v", spray.Input)
	}
}

func TestPlanFromStateKeepsNonHTTPServicesForNucleiOnly(t *testing.T) {
	actions := PlanFromState(State{
		Target:       "127.0.0.1",
		URLs:         []string{"tcp://127.0.0.1:6379"},
		Fingerprints: []string{"redis"},
		TemplateIDs:  []string{"exposed-redis"},
	})
	if findAction(actions, "gogo") != nil {
		t.Fatalf("non-HTTP service should not fall back to gogo: %#v", actions)
	}
	if findAction(actions, "spray") != nil || findAction(actions, "fingers") != nil {
		t.Fatalf("TCP service should not trigger spray/fingers: %#v", actions)
	}
	nuclei := findAction(actions, "nuclei")
	if nuclei == nil {
		t.Fatalf("expected nuclei for TCP service templates: %#v", actions)
	}
	targets, ok := nuclei.Input["targets"].([]string)
	if !ok || len(targets) != 1 || targets[0] != "tcp://127.0.0.1:6379" {
		t.Fatalf("expected TCP nuclei target, got %#v", nuclei.Input)
	}
}

func TestPlanFromStateReplansFingersForSprayURLs(t *testing.T) {
	actions := PlanFromState(State{
		Target:       "example.com",
		BaseURLs:     []string{"https://example.com"},
		SprayURLs:    []string{"https://example.com/actuator/env"},
		URLs:         []string{"https://example.com", "https://example.com/actuator/env"},
		Fingerprints: []string{"nginx"},
	})
	fingers := findAction(actions, "fingers")
	if fingers == nil {
		t.Fatalf("missing fingers action for spray URL: %#v", actions)
	}
	urls, ok := fingers.Input["urls"].([]string)
	if !ok || len(urls) != 1 || urls[0] != "https://example.com/actuator/env" {
		t.Fatalf("expected spray URL fingerprint target, got %#v", fingers.Input)
	}
}

func TestPlanFromStateFiltersCompletedAndRunningActions(t *testing.T) {
	base := State{
		Target:      "example.com",
		URLs:        []string{"https://example.com"},
		TemplateIDs: []string{"CVE-2020-14882"},
	}
	actions := PlanFromState(base)
	nuclei := findAction(actions, "nuclei")
	if nuclei == nil {
		t.Fatalf("missing nuclei action: %#v", actions)
	}

	base.Actions = []data.ActionRecord{{ID: nuclei.ID, Status: "completed"}}
	actions = PlanFromState(base)
	if findAction(actions, "nuclei") != nil {
		t.Fatalf("completed action should be filtered: %#v", actions)
	}

	base.Actions = []data.ActionRecord{{ID: nuclei.ID, Status: "failed"}}
	actions = PlanFromState(base)
	if findAction(actions, "nuclei") == nil {
		t.Fatalf("failed action should be returned for retry: %#v", actions)
	}
}

func TestPlanFromStateFiltersCoveredActionInputs(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"base_urls":     []string{"https://example.com"},
		"wordlist_mode": "full",
		"_planner": map[string]interface{}{
			"dedup_key": actionDedupKey("example.com", "spray", "full", joinKey([]string{"https://example.com"})),
		},
	})
	actions := PlanFromState(State{
		Target:   "example.com",
		BaseURLs: []string{"https://example.com", "https://admin.example.com"},
		URLs:     []string{"https://example.com", "https://admin.example.com"},
		Actions:  []data.ActionRecord{{Artifact: "spray", Input: raw, Status: "completed"}},
	})
	spray := findAction(actions, "spray")
	if spray == nil {
		t.Fatalf("expected spray action for uncovered base URL: %#v", actions)
	}
	baseURLs, ok := spray.Input["base_urls"].([]string)
	if !ok || len(baseURLs) != 1 || baseURLs[0] != "https://admin.example.com" {
		t.Fatalf("expected only uncovered base URL, got %#v", spray.Input)
	}
}

func TestPlanFromStatePrioritizesHighValueSprayURLsForNuclei(t *testing.T) {
	actions := PlanFromState(State{
		Target:        "example.com",
		BaseURLs:      []string{"https://example.com"},
		SprayURLs:     []string{"https://example.com/readme.txt", "https://example.com/actuator/env"},
		HighValueURLs: []string{"https://example.com/actuator/env"},
		URLs:          []string{"https://example.com", "https://example.com/readme.txt", "https://example.com/actuator/env"},
		TemplateIDs:   []string{"springboot-actuator"},
	})
	nuclei := findAction(actions, "nuclei")
	if nuclei == nil {
		t.Fatalf("missing nuclei action: %#v", actions)
	}
	targets, ok := nuclei.Input["targets"].([]string)
	if !ok || len(targets) != 1 || targets[0] != "https://example.com/actuator/env" {
		t.Fatalf("expected high-value target only, got %#v", nuclei.Input)
	}
}

func TestPlanFromStateScoresPreciseTemplateAboveBroadTags(t *testing.T) {
	precise := PlanFromState(State{
		Target:       "example.com",
		URLs:         []string{"https://example.com"},
		Fingerprints: []string{"weblogic"},
		TemplateIDs:  []string{"CVE-2020-14882"},
		CVEs: []data.Asset{{
			Value:    "CVE-2020-14882",
			Priority: 100,
			Severity: "critical",
			Status:   "candidate",
		}},
	})
	broad := PlanFromState(State{
		Target:       "example.com",
		URLs:         []string{"https://example.com"},
		Fingerprints: []string{"weblogic"},
		Tags:         []string{"weblogic"},
	})
	preciseNuclei := findAction(precise, "nuclei")
	broadNuclei := findAction(broad, "nuclei")
	if preciseNuclei == nil || broadNuclei == nil {
		t.Fatalf("missing nuclei actions: precise=%#v broad=%#v", precise, broad)
	}
	if preciseNuclei.Score <= broadNuclei.Score {
		t.Fatalf("expected precise score > broad score, got precise=%d broad=%d", preciseNuclei.Score, broadNuclei.Score)
	}
}

func TestPlanFromStateUsesGraphEvidenceForScoring(t *testing.T) {
	base := State{
		Target:       "example.com",
		URLs:         []string{"https://example.com"},
		Fingerprints: []string{"weblogic"},
		TemplateIDs:  []string{"CVE-2020-14882"},
	}
	withoutEvidence := findAction(PlanFromState(base), "nuclei")
	if withoutEvidence == nil {
		t.Fatalf("missing nuclei action")
	}

	base.Evidence = []data.EvidenceRecord{
		{Type: "product", Value: "Oracle WebLogic Server", Priority: 20, Status: "candidate"},
		{Type: "cve", Value: "CVE-2020-14882", Priority: 100, Severity: "critical", Status: "candidate"},
		{Type: "template", Value: "CVE-2020-14882", Priority: 70, Status: "candidate"},
		{
			Type:     "intel",
			Value:    "CVE-2020-14882 KEV EPSS 0.99 CVSS 9.8",
			Priority: 100,
			Severity: "CRITICAL",
			Status:   "candidate",
			Path: []data.EvidencePathStep{
				{Type: "fingerprint", Value: "weblogic"},
				{Relation: "identifies_product", Type: "product", Value: "Oracle WebLogic Server"},
				{Relation: "affected_by", Type: "cve", Value: "CVE-2020-14882"},
				{Relation: "has_intel", Type: "intel", Value: "CVE-2020-14882 KEV EPSS 0.99 CVSS 9.8"},
			},
		},
	}
	withEvidence := findAction(PlanFromState(base), "nuclei")
	if withEvidence == nil {
		t.Fatalf("missing nuclei action with evidence")
	}
	if withEvidence.Score <= withoutEvidence.Score {
		t.Fatalf("expected graph evidence to improve score, without=%d with=%d", withoutEvidence.Score, withEvidence.Score)
	}
	if !hasEvidence(withEvidence.Evidence, "intel", "CVE-2020-14882 KEV EPSS 0.99 CVSS 9.8") {
		t.Fatalf("missing intel evidence: %#v", withEvidence.Evidence)
	}
	intel := findEvidence(withEvidence.Evidence, "intel", "CVE-2020-14882 KEV EPSS 0.99 CVSS 9.8")
	if intel == nil || len(intel.Path) != 4 {
		t.Fatalf("expected evidence path, got %#v", intel)
	}
}

func TestScoreActionRewardsCompleteEvidenceChain(t *testing.T) {
	shallow := Action{
		Artifact: "nuclei",
		Priority: 70,
		Cost:     35,
		Risk:     "medium",
		Evidence: []Evidence{{Type: "product", Value: "Spring Boot", Priority: 40}},
	}
	complete := shallow
	complete.Evidence = []Evidence{{
		Type:     "intel",
		Value:    "CVE-2021-44228 KEV EPSS 0.97 CVSS 10",
		Priority: 100,
		Severity: "critical",
		Status:   "candidate",
		Path: []EvidencePathStep{
			{Type: "fingerprint", Value: "log4j"},
			{Relation: "identifies_product", Type: "product", Value: "Apache Log4j"},
			{Relation: "affected_by", Type: "cve", Value: "CVE-2021-44228"},
			{Relation: "has_template", Type: "template", Value: "CVE-2021-44228"},
			{Relation: "has_intel", Type: "intel", Value: "CVE-2021-44228 KEV EPSS 0.97 CVSS 10"},
		},
	}}
	if scoreAction(complete) <= scoreAction(shallow) {
		t.Fatalf("expected complete evidence chain to score higher, shallow=%d complete=%d", scoreAction(shallow), scoreAction(complete))
	}
}

func TestPlanDAGFromActionsOrdersAndLinksStages(t *testing.T) {
	actions := []Action{
		{
			ID:       "nuclei-1",
			Target:   "example.com",
			Artifact: "nuclei",
			Input:    map[string]interface{}{"targets": []string{"https://example.com"}, "ids": []string{"CVE-2020-14882"}},
			Priority: 80,
			Score:    100,
			DedupKey: "nuclei-key",
		},
		{
			ID:       "spray-1",
			Target:   "example.com",
			Artifact: "spray",
			Input:    map[string]interface{}{"base_urls": []string{"https://example.com"}, "wordlist_mode": "full"},
			Priority: 80,
			Score:    60,
			DedupKey: "spray-key",
		},
		{
			ID:       "fingers-1",
			Target:   "example.com",
			Artifact: "fingers",
			Input:    map[string]interface{}{"mode": "http_match", "urls": []string{"https://example.com"}},
			Priority: 50,
			Score:    50,
			DedupKey: "fingers-key",
		},
	}
	plan := PlanDAGFromActions("example.com", "camp-1", actions)
	if len(plan.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %#v", plan.Nodes)
	}
	if plan.Nodes[0].Artifact != "fingers" || plan.Nodes[1].Artifact != "spray" || plan.Nodes[2].Artifact != "nuclei" {
		t.Fatalf("unexpected DAG order: %#v", plan.Nodes)
	}
	fingersID := plan.Nodes[0].ID
	sprayID := plan.Nodes[1].ID
	if !contains(plan.Nodes[1].DependsOn, fingersID) {
		t.Fatalf("expected spray to depend on fingers, got %#v", plan.Nodes[1].DependsOn)
	}
	if !contains(plan.Nodes[2].DependsOn, fingersID) || !contains(plan.Nodes[2].DependsOn, sprayID) {
		t.Fatalf("expected nuclei to depend on fingers and spray, got %#v", plan.Nodes[2].DependsOn)
	}
	if plan.Nodes[2].RunIf == nil || plan.Nodes[2].RunIf.CampaignID != "camp-1" {
		t.Fatalf("expected nuclei run_if with campaign, got %#v", plan.Nodes[2].RunIf)
	}
}

func findAction(actions []Action, artifact string) *Action {
	for i := range actions {
		if actions[i].Artifact == artifact {
			return &actions[i]
		}
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasEvidence(values []Evidence, evidenceType, value string) bool {
	return findEvidence(values, evidenceType, value) != nil
}

func findEvidence(values []Evidence, evidenceType, value string) *Evidence {
	for _, evidence := range values {
		if evidence.Type == evidenceType && evidence.Value == value {
			return &evidence
		}
	}
	return nil
}
