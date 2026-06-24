package data

import "encoding/json"

// WorkItemEnvelope is the canonical JSON payload stored in WorkItem.Input for
// scheduled workflow items.
type WorkItemEnvelope struct {
	IP            string                    `json:"ip,omitempty"`
	Ports         string                    `json:"ports,omitempty"`
	SourceTarget  string                    `json:"source_target,omitempty"`
	Target        string                    `json:"target,omitempty"`
	ActionInput   map[string]interface{}    `json:"input,omitempty"`
	NodeID        string                    `json:"node_id,omitempty"`
	Reason        string                    `json:"reason,omitempty"`
	Risk          string                    `json:"risk,omitempty"`
	Cost          int                       `json:"cost,omitempty"`
	DedupKey      string                    `json:"dedup_key,omitempty"`
	RunIf         *WorkItemConditionRequest `json:"run_if,omitempty"`
	Iteration     int                       `json:"iteration,omitempty"`
	MaxIterations int                       `json:"max_iterations,omitempty"`
	ShardIndex    int                       `json:"shard_index,omitempty"`
}

type WorkItemConditionRequest struct {
	Target     string                   `json:"target"`
	CampaignID string                   `json:"campaign_id,omitempty"`
	All        []WorkItemAssetCondition `json:"all,omitempty"`
	Any        []WorkItemAssetCondition `json:"any,omitempty"`
}

type WorkItemAssetCondition struct {
	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Status    string `json:"status,omitempty"`
	EventType string `json:"event_type,omitempty"`
	MinCount  int    `json:"min_count,omitempty"`
}

type WorkItemConditionResult struct {
	OK      bool                          `json:"ok"`
	Counts  []WorkItemAssetConditionCount `json:"counts,omitempty"`
	Message string                        `json:"message,omitempty"`
}

type WorkItemAssetConditionCount struct {
	Condition WorkItemAssetCondition `json:"condition"`
	Count     int                    `json:"count"`
	OK        bool                   `json:"ok"`
}

func ParseWorkItemEnvelope(item WorkItem) WorkItemEnvelope {
	var out WorkItemEnvelope
	_ = json.Unmarshal(item.Input, &out)
	return out
}
