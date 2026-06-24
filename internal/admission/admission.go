package admission

import (
	"strconv"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

const (
	StatusAdmitted         = "admitted"
	StatusSkipped          = "skipped"
	StatusRejected         = "rejected"
	StatusApprovalRequired = "approval_required"
)

type Request struct {
	CampaignID   string          `json:"campaign_id,omitempty"`
	BatchID      string          `json:"batch_id,omitempty"`
	ScopeTargets []string        `json:"scope_targets,omitempty"`
	Items        []data.WorkItem `json:"items,omitempty"`
	Existing     []data.WorkItem `json:"existing,omitempty"`
}

type Result struct {
	Admitted  []data.WorkItem `json:"admitted,omitempty"`
	Decisions []Decision      `json:"decisions,omitempty"`
}

type Decision struct {
	ItemID string `json:"item_id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type Policy struct {
	scope data.ScopeSet
}

func NewPolicy(scopeTargets []string) Policy {
	return Policy{scope: data.NewScopeSet(scopeTargets)}
}

func Admit(request Request) Result {
	policy := NewPolicy(request.ScopeTargets)
	return policy.Admit(request.Items, request.Existing)
}

func (p Policy) Admit(items, existing []data.WorkItem) Result {
	seen := blockingKeys(existing)
	result := Result{Admitted: make([]data.WorkItem, 0, len(items)), Decisions: make([]Decision, 0, len(items))}
	for _, item := range items {
		decision := p.Decide(item, seen)
		result.Decisions = append(result.Decisions, decision)
		if decision.Status != StatusAdmitted {
			continue
		}
		result.Admitted = append(result.Admitted, item)
		rememberBlockingKeys(seen, item)
	}
	return result
}

func (p Policy) Decide(item data.WorkItem, seen map[string]bool) Decision {
	if item.ID == "" {
		return Decision{ItemID: item.ID, Status: StatusRejected, Reason: "missing work item id"}
	}
	if seen[itemIDKey(item)] {
		return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "work item already planned"}
	}
	envelope := data.ParseWorkItemEnvelope(item)
	if key := actionBaseKey(item, envelope); key != "" && seen[key] {
		return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "action already planned"}
	}
	if key := actionPreciseKey(item, envelope); key != "" && seen[key] {
		return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "action shard already planned"}
	}
	if requiresApproval(item, envelope) {
		return Decision{ItemID: item.ID, Status: StatusApprovalRequired, Reason: "action requires manual approval"}
	}
	if isNoise(envelope.ActionInput) {
		return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "noise result cannot schedule actions"}
	}
	if !allowsWorkItem(p.scope, item, envelope) {
		return Decision{ItemID: item.ID, Status: StatusRejected, Reason: "target is outside campaign scope"}
	}
	return Decision{ItemID: item.ID, Status: StatusAdmitted}
}

func blockingKeys(items []data.WorkItem) map[string]bool {
	seen := make(map[string]bool, len(items)*2)
	for _, item := range items {
		if !data.AdmissionBlockingWorkItemStatus(item.Status) {
			continue
		}
		rememberExistingBlockingKeys(seen, item)
	}
	return seen
}

func rememberBlockingKeys(seen map[string]bool, item data.WorkItem) {
	seen[itemIDKey(item)] = true
	envelope := data.ParseWorkItemEnvelope(item)
	if key := actionPreciseKey(item, envelope); key != "" {
		seen[key] = true
	}
}

func rememberExistingBlockingKeys(seen map[string]bool, item data.WorkItem) {
	rememberBlockingKeys(seen, item)
	envelope := data.ParseWorkItemEnvelope(item)
	if key := actionBaseKey(item, envelope); key != "" {
		seen[key] = true
	}
}

func itemIDKey(item data.WorkItem) string {
	return "id:" + item.ID
}

func actionBaseKey(item data.WorkItem, envelope data.WorkItemEnvelope) string {
	if envelope.DedupKey == "" {
		return ""
	}
	return strings.Join([]string{"action", item.CampaignID, item.BatchID, item.Target, item.Type, item.Artifact, envelope.DedupKey}, "\x00")
}

func actionPreciseKey(item data.WorkItem, envelope data.WorkItemEnvelope) string {
	base := actionBaseKey(item, envelope)
	if base == "" || envelope.ShardIndex <= 0 {
		return base
	}
	return strings.Join([]string{base, "shard", strconv.Itoa(envelope.ShardIndex)}, "\x00")
}

func requiresApproval(item data.WorkItem, envelope data.WorkItemEnvelope) bool {
	if item.Artifact == "zombie" {
		return true
	}
	risk := strings.ToLower(strings.TrimSpace(envelope.Risk))
	if risk == "dangerous" || risk == "approval_required" {
		return true
	}
	for _, value := range []string{item.Type, item.Artifact, stringValue(envelope.ActionInput, "mode"), stringValue(envelope.ActionInput, "action")} {
		value = strings.ToLower(value)
		if strings.Contains(value, "bruteforce") ||
			strings.Contains(value, "brute") ||
			strings.Contains(value, "login") ||
			strings.Contains(value, "write") ||
			strings.Contains(value, "exploit") {
			return true
		}
	}
	return false
}

func isNoise(input map[string]interface{}) bool {
	if boolValue(input, "fuzzy") {
		return true
	}
	if raw, ok := input["valid"]; ok {
		if valid, ok := raw.(bool); ok && !valid {
			return true
		}
	}
	status := strings.ToLower(strings.TrimSpace(stringValue(input, "status")))
	return status == "noise" || status == "soft404"
}

func boolValue(input map[string]interface{}, key string) bool {
	if input == nil {
		return false
	}
	value, _ := input[key].(bool)
	return value
}

func stringValue(input map[string]interface{}, key string) string {
	if input == nil {
		return ""
	}
	value, _ := input[key].(string)
	return value
}

func allowsWorkItem(scope data.ScopeSet, item data.WorkItem, envelope data.WorkItemEnvelope) bool {
	if scope.Empty() {
		return true
	}
	values := make([]string, 0, 8)
	for _, key := range []string{"base_urls", "urls", "targets"} {
		values = append(values, data.ActionInputStrings(envelope.ActionInput, key)...)
	}
	if len(values) == 0 {
		values = []string{item.Target, envelope.Target}
	}
	for _, value := range values {
		host := data.NormalizeHostLike(value)
		if host == "" {
			continue
		}
		if data.IsLoopbackHost(host) && !scope.Contains(host) {
			return false
		}
		if !scope.Contains(host) {
			return false
		}
	}
	return true
}
