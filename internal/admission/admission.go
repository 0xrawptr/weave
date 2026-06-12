package admission

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
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
	scope scopeSet
}

func NewPolicy(scopeTargets []string) Policy {
	return Policy{scope: newScopeSet(scopeTargets)}
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
	envelope := parseEnvelope(item)
	if envelope.ShardIndex <= 0 {
		if key := actionKey(item, envelope); key != "" && seen[key] {
			return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "action already planned"}
		}
	}
	if requiresApproval(item, envelope) {
		return Decision{ItemID: item.ID, Status: StatusApprovalRequired, Reason: "action requires manual approval"}
	}
	if isNoise(envelope.ActionInput) {
		return Decision{ItemID: item.ID, Status: StatusSkipped, Reason: "noise result cannot schedule actions"}
	}
	if !p.scope.allowsWorkItem(item, envelope) {
		return Decision{ItemID: item.ID, Status: StatusRejected, Reason: "target is outside campaign scope"}
	}
	return Decision{ItemID: item.ID, Status: StatusAdmitted}
}

type workItemEnvelope struct {
	Target      string                 `json:"target,omitempty"`
	ActionInput map[string]interface{} `json:"input,omitempty"`
	DedupKey    string                 `json:"dedup_key,omitempty"`
	Risk        string                 `json:"risk,omitempty"`
	ShardIndex  int                    `json:"shard_index,omitempty"`
}

func parseEnvelope(item data.WorkItem) workItemEnvelope {
	var out workItemEnvelope
	_ = json.Unmarshal(item.Input, &out)
	return out
}

func blockingKeys(items []data.WorkItem) map[string]bool {
	seen := make(map[string]bool, len(items)*2)
	for _, item := range items {
		if !blocks(item.Status) {
			continue
		}
		rememberBlockingKeys(seen, item)
	}
	return seen
}

func rememberBlockingKeys(seen map[string]bool, item data.WorkItem) {
	seen[itemIDKey(item)] = true
	envelope := parseEnvelope(item)
	if envelope.ShardIndex <= 0 {
		if key := actionKey(item, envelope); key != "" {
			seen[key] = true
		}
	}
}

func itemIDKey(item data.WorkItem) string {
	return "id:" + item.ID
}

func actionKey(item data.WorkItem, envelope workItemEnvelope) string {
	if envelope.DedupKey == "" {
		return ""
	}
	return strings.Join([]string{"action", item.CampaignID, item.BatchID, item.Target, item.Type, item.Artifact, envelope.DedupKey}, "\x00")
}

func blocks(status string) bool {
	switch status {
	case data.WorkItemStatusPending,
		data.WorkItemStatusStarting,
		data.WorkItemStatusRunning,
		data.WorkItemStatusCompleted,
		data.WorkItemStatusRetryWaiting,
		data.WorkItemStatusPaused:
		return true
	default:
		return false
	}
}

func requiresApproval(item data.WorkItem, envelope workItemEnvelope) bool {
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

type scopeSet struct {
	empty    bool
	hosts    map[string]bool
	domains  []string
	prefixes []netip.Prefix
}

func newScopeSet(targets []string) scopeSet {
	out := scopeSet{hosts: map[string]bool{}}
	for _, target := range targets {
		target = normalizeHostLike(target)
		if target == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(target); err == nil {
			out.prefixes = append(out.prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(target); err == nil {
			out.prefixes = append(out.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		host := strings.ToLower(target)
		out.hosts[host] = true
		if net.ParseIP(host) == nil {
			out.domains = append(out.domains, host)
		}
	}
	out.empty = len(out.hosts) == 0 && len(out.prefixes) == 0
	return out
}

func (s scopeSet) allowsWorkItem(item data.WorkItem, envelope workItemEnvelope) bool {
	if s.empty {
		return true
	}
	values := make([]string, 0, 8)
	for _, key := range []string{"base_urls", "urls", "targets"} {
		values = append(values, stringSlice(envelope.ActionInput, key)...)
	}
	if len(values) == 0 {
		values = []string{item.Target, envelope.Target}
	}
	for _, value := range values {
		host := normalizeHostLike(value)
		if host == "" {
			continue
		}
		if isLoopbackHost(host) && !s.contains(host) {
			return false
		}
		if !s.contains(host) {
			return false
		}
	}
	return true
}

func (s scopeSet) contains(host string) bool {
	host = normalizeHostLike(host)
	if host == "" {
		return true
	}
	if s.hosts[strings.ToLower(host)] {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		for _, prefix := range s.prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	host = strings.ToLower(host)
	for _, domain := range s.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func normalizeHostLike(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.Trim(u.Hostname(), "[]"))
	}
	if strings.Contains(raw, "/") {
		if _, err := netip.ParsePrefix(raw); err == nil {
			return raw
		}
		return ""
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	} else if strings.Count(raw, ":") == 1 {
		if h, _, err := net.SplitHostPort(raw); err == nil {
			host = h
		} else {
			parts := strings.Split(raw, ":")
			if len(parts) == 2 {
				host = parts[0]
			}
		}
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(normalizeHostLike(host))
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func stringSlice(input map[string]interface{}, key string) []string {
	if input == nil {
		return nil
	}
	switch value := input[key].(type) {
	case []string:
		return append([]string{}, value...)
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{value}
	default:
		return nil
	}
}
