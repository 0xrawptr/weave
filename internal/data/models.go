package data

import (
	"time"
)

const (
	WorkItemStatusPending      = "pending"
	WorkItemStatusRunning      = "running"
	WorkItemStatusCompleted    = "completed"
	WorkItemStatusFailed       = "failed"
	WorkItemStatusRetryWaiting = "retry_waiting"
	WorkItemStatusPaused       = "paused"
	WorkItemStatusCancelled    = "cancelled"
	WorkItemStatusSkipped      = "skipped"
	WorkItemStatusDead         = "dead"
)

// Target represents a scan target.
type Target struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // domain, ip, url, cidr
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

// Campaign is the top-level unit for a HW/SRC/ASM operation.
type Campaign struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"` // active, paused, completed, archived
	Targets     []string  `json:"targets,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CampaignTarget records an input scope item attached to a campaign.
type CampaignTarget struct {
	ID         string    `json:"id"`
	CampaignID string    `json:"campaign_id"`
	Type       string    `json:"type"` // domain, ip, cidr, url, unknown
	Value      string    `json:"value"`
	Status     string    `json:"status"` // active, excluded
	CreatedAt  time.Time `json:"created_at"`
}

// Asset represents a discovered asset.
type Asset struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaign_id,omitempty"`
	Type        string    `json:"type"` // domain, subdomain, ip, port, url, service, fingerprint, template, cve, vulnerability
	Value       string    `json:"value"`
	Source      string    `json:"source"` // which artifact discovered it
	TargetID    string    `json:"target_id"`
	RawData     []byte    `json:"raw_data"` // original JSON from artifact
	Confidence  float64   `json:"confidence,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Priority    int       `json:"priority,omitempty"`
	Status      string    `json:"status,omitempty"` // observed, queued, noise, candidate, confirmed, false_positive, ignored, interesting
	Lifecycle   string    `json:"lifecycle_status,omitempty"`
	RawHash     string    `json:"raw_hash,omitempty"`
	SourceRunID string    `json:"source_run_id,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
}

// AssetEvent records lifecycle transitions for an asset.
type AssetEvent struct {
	ID           string    `json:"id"`
	AssetID      string    `json:"asset_id"`
	CampaignID   string    `json:"campaign_id,omitempty"`
	EventType    string    `json:"event_type"` // new, reproduced, changed, disappeared, status_changed
	PreviousHash string    `json:"previous_hash,omitempty"`
	NewHash      string    `json:"new_hash,omitempty"`
	Source       string    `json:"source,omitempty"`
	TargetID     string    `json:"target_id,omitempty"`
	Details      []byte    `json:"details,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
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

// ArtifactStat records engine-neutral execution counters emitted by SDK artifacts.
type ArtifactStat struct {
	ID         string    `json:"id"`
	CampaignID string    `json:"campaign_id,omitempty"`
	WorkflowID string    `json:"workflow_id,omitempty"`
	Artifact   string    `json:"artifact"`
	Target     string    `json:"target"`
	Engine     string    `json:"engine"`
	Task       string    `json:"task"`
	Targets    int64     `json:"targets,omitempty"`
	Tasks      int64     `json:"tasks,omitempty"`
	Requests   int64     `json:"requests,omitempty"`
	Results    int64     `json:"results,omitempty"`
	Errors     int64     `json:"errors,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ActionRecord tracks planner/manual action execution across workflows.
type ActionRecord struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaign_id,omitempty"`
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

// BatchRun tracks a large target batch, such as a HW CIDR portscan batch.
type BatchRun struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaign_id,omitempty"`
	WorkflowID  string    `json:"workflow_id"`
	Type        string    `json:"type"`
	Target      string    `json:"target"`
	Ports       string    `json:"ports,omitempty"`
	Status      string    `json:"status"` // running, completed, failed, partial
	TotalChunks int       `json:"total_chunks"`
	Completed   int       `json:"completed"`
	Failed      int       `json:"failed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BatchChunk tracks a single executable chunk in a batch run.
type BatchChunk struct {
	ID          string    `json:"id"`
	BatchID     string    `json:"batch_id"`
	Target      string    `json:"target"`
	Chunk       string    `json:"chunk"`
	WorkflowID  string    `json:"workflow_id"`
	Status      string    `json:"status"` // pending, running, planning, completed, partial, failed
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// WorkItem is the durable scheduling unit for large ASM campaigns.
type WorkItem struct {
	ID             string    `json:"id"`
	CampaignID     string    `json:"campaign_id,omitempty"`
	BatchID        string    `json:"batch_id,omitempty"`
	ParentID       string    `json:"parent_id,omitempty"`
	Type           string    `json:"type"` // portscan_chunk, planned_dag_followup, spray_shard, nuclei_group
	Target         string    `json:"target"`
	Artifact       string    `json:"artifact"`
	Queue          string    `json:"queue,omitempty"`
	Input          []byte    `json:"input,omitempty"`
	Priority       int       `json:"priority"`
	Status         string    `json:"status"` // pending, running, completed, failed, retry_waiting, paused, cancelled, skipped, dead
	Attempts       int       `json:"attempts"`
	MaxAttempts    int       `json:"max_attempts"`
	WorkflowID     string    `json:"workflow_id,omitempty"`
	Error          string    `json:"error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	HeartbeatAt    time.Time `json:"heartbeat_at"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
}

type WorkItemClaimRequest struct {
	CampaignID            string `json:"campaign_id,omitempty"`
	BatchID               string `json:"batch_id,omitempty"`
	Type                  string `json:"type,omitempty"`
	Artifact              string `json:"artifact,omitempty"`
	Queue                 string `json:"queue,omitempty"`
	Target                string `json:"target,omitempty"`
	WorkflowID            string `json:"workflow_id,omitempty"`
	LeaseSeconds          int    `json:"lease_seconds,omitempty"`
	MaxRunning            int    `json:"max_running,omitempty"`
	MaxRunningPerArtifact int    `json:"max_running_per_artifact,omitempty"`
	MaxRunningPerCampaign int    `json:"max_running_per_campaign,omitempty"`
	MaxRunningPerTarget   int    `json:"max_running_per_target,omitempty"`
}

type WorkItemHeartbeatRequest struct {
	ID           string `json:"id"`
	WorkflowID   string `json:"workflow_id,omitempty"`
	LeaseSeconds int    `json:"lease_seconds,omitempty"`
}

type WorkItemFilter struct {
	CampaignID string `json:"campaign_id,omitempty"`
	BatchID    string `json:"batch_id,omitempty"`
	Status     string `json:"status,omitempty"`
	Type       string `json:"type,omitempty"`
	Artifact   string `json:"artifact,omitempty"`
	Target     string `json:"target,omitempty"`
	ID         string `json:"id,omitempty"`
}

type WorkItemRetryRequest struct {
	Filter        WorkItemFilter `json:"filter"`
	FromStatuses  []string       `json:"from_statuses,omitempty"`
	ResetAttempts bool           `json:"reset_attempts,omitempty"`
}

type WorkItemBulkResult struct {
	Matched int `json:"matched"`
	Updated int `json:"updated"`
}

type WorkItemGroupSummary struct {
	Key                string `json:"key"`
	Total              int    `json:"total"`
	Pending            int    `json:"pending"`
	Running            int    `json:"running"`
	Completed          int    `json:"completed"`
	Failed             int    `json:"failed"`
	RetryWaiting       int    `json:"retry_waiting"`
	Paused             int    `json:"paused"`
	Cancelled          int    `json:"cancelled"`
	Skipped            int    `json:"skipped"`
	Dead               int    `json:"dead"`
	Queued             int    `json:"queued"`
	Done               int    `json:"done"`
	Error              int    `json:"error"`
	ProgressPercent    int    `json:"progress_percent"`
	AvgDurationMs      int64  `json:"avg_duration_ms,omitempty"`
	ThroughputPerMin   int    `json:"throughput_per_min,omitempty"`
	ETASeconds         int64  `json:"eta_seconds,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	LastErrorUpdatedAt string `json:"last_error_updated_at,omitempty"`
}

type WorkItemProgressSummary struct {
	Total            int                    `json:"total"`
	ByStatus         map[string]int         `json:"by_status"`
	Overall          WorkItemGroupSummary   `json:"overall"`
	ByType           []WorkItemGroupSummary `json:"by_type"`
	ByQueue          []WorkItemGroupSummary `json:"by_queue"`
	ByArtifact       []WorkItemGroupSummary `json:"by_artifact"`
	GeneratedAt      time.Time              `json:"generated_at"`
	ETASeconds       int64                  `json:"eta_seconds,omitempty"`
	ThroughputPerMin int                    `json:"throughput_per_min,omitempty"`
}

type ArtifactStatSummary struct {
	Artifact         string `json:"artifact"`
	TotalRuns        int    `json:"total_runs"`
	Targets          int64  `json:"targets,omitempty"`
	Tasks            int64  `json:"tasks,omitempty"`
	Requests         int64  `json:"requests,omitempty"`
	Results          int64  `json:"results,omitempty"`
	Errors           int64  `json:"errors,omitempty"`
	DurationMs       int64  `json:"duration_ms,omitempty"`
	AvgDurationMs    int64  `json:"avg_duration_ms,omitempty"`
	ErrorRatePercent int    `json:"error_rate_percent,omitempty"`
	ThroughputPerMin int64  `json:"throughput_per_min,omitempty"`
}

// RawEvent stores artifact output exactly as produced, before any transformation.
type RawEvent struct {
	ID         string    `json:"id"`
	CampaignID string    `json:"campaign_id,omitempty"`
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
