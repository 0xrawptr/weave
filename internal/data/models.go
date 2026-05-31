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
	ID        string    `json:"id"`
	Type      string    `json:"type"` // domain, subdomain, ip, port, url, service, fingerprint, vuln
	Value     string    `json:"value"`
	Source    string    `json:"source"`  // which artifact discovered it
	TargetID  string    `json:"target_id"`
	RawData   []byte    `json:"raw_data"`  // original JSON from artifact
	CreatedAt time.Time `json:"created_at"`
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

// AssetRelation represents an edge between two assets in the graph.
type AssetRelation struct {
	FromAssetID string `json:"from_asset_id"`
	ToAssetID   string `json:"to_asset_id"`
	Type        string `json:"type"` // resolves_to, has_port, runs_service, has_fingerprint, has_vuln
}
