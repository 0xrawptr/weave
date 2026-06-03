package data

import (
	"time"
)

// Target represents a scan target.
type Target struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // domain, ip, url, cidr
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

// Asset represents a discovered asset.
type Asset struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // domain, subdomain, ip, port, url, service, fingerprint, template, cve, vulnerability
	Value       string    `json:"value"`
	Source      string    `json:"source"` // which artifact discovered it
	TargetID    string    `json:"target_id"`
	RawData     []byte    `json:"raw_data"` // original JSON from artifact
	Confidence  float64   `json:"confidence,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Priority    int       `json:"priority,omitempty"`
	Status      string    `json:"status,omitempty"` // observed, candidate, confirmed, false_positive, ignored, interesting
	SourceRunID string    `json:"source_run_id,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
}

// Scan represents a workflow execution record.
type Scan struct {
	ID           string    `json:"id"`
	WorkflowID   string    `json:"workflow_id"`
	WorkflowType string    `json:"workflow_type"`
	TargetID     string    `json:"target_id"`
	Status       string    `json:"status"` // pending, running, completed, failed, cancelled
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ScanResult represents the output of a single artifact within a workflow.
type ScanResult struct {
	ID         string    `json:"id"`
	ScanID     string    `json:"scan_id"`
	Artifact   string    `json:"artifact"`
	Input      []byte    `json:"input"`
	Output     []byte    `json:"output"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

// ActionRecord tracks planner/manual action execution across workflows.
type ActionRecord struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Artifact    string    `json:"artifact"`
	Input       []byte    `json:"input"`
	Priority    int       `json:"priority"`
	Reason      string    `json:"reason"`
	Status      string    `json:"status"` // candidate, running, completed, failed, skipped
	Attempts    int       `json:"attempts"`
	WorkflowID  string    `json:"workflow_id"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// RawEvent stores artifact output exactly as produced, before any transformation.
type RawEvent struct {
	ID         string    `json:"id"`
	Artifact   string    `json:"artifact"`
	TargetID   string    `json:"target_id"`
	TargetType string    `json:"target_type"` // "cidr", "domain", "ip"
	WorkflowID string    `json:"workflow_id"`
	Data       []byte    `json:"data"`
	CreatedAt  time.Time `json:"created_at"`
}

// AssetRelation represents an edge between two assets in the graph.
type AssetRelation struct {
	FromAssetID string `json:"from_asset_id"`
	ToAssetID   string `json:"to_asset_id"`
	Type        string `json:"type"` // resolves_to, has_port, runs_service, has_fingerprint, has_vuln
}

// EvidenceRecord is a planner-facing view of graph knowledge.
type EvidenceRecord struct {
	Type       string             `json:"type"`
	Value      string             `json:"value"`
	Source     string             `json:"source,omitempty"`
	Confidence float64            `json:"confidence,omitempty"`
	Severity   string             `json:"severity,omitempty"`
	Priority   int                `json:"priority,omitempty"`
	Status     string             `json:"status,omitempty"`
	Path       []EvidencePathStep `json:"path,omitempty"`
}

// EvidencePathStep describes one hop in a knowledge evidence chain.
type EvidencePathStep struct {
	Relation string `json:"relation,omitempty"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}
