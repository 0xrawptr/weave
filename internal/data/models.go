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

	ScheduleNow   = "now"
	ScheduleBatch = "batch"
)

func NormalizeSchedule(schedule string) string {
	switch schedule {
	case ScheduleNow:
		return ScheduleNow
	default:
		return ScheduleBatch
	}
}

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
	Phase       string    `json:"phase,omitempty"`
	PhaseReason string    `json:"phase_reason,omitempty"`
	Targets     []string  `json:"targets,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CampaignPhaseEvent records explicit campaign controller state transitions.
type CampaignPhaseEvent struct {
	ID         string    `json:"id"`
	CampaignID string    `json:"campaign_id"`
	BatchID    string    `json:"batch_id,omitempty"`
	FromPhase  string    `json:"from_phase,omitempty"`
	ToPhase    string    `json:"to_phase"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
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

// AssetEvidence stores planner/knowledge evidence observed on an asset. It is
// intentionally separate from assets: values such as "nginx", "linkfinder" or a
// CVE are evidence about an attack surface, not an attack surface by themselves.
type AssetEvidence struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaign_id,omitempty"`
	TargetID    string    `json:"target_id"`
	SubjectID   string    `json:"subject_id,omitempty"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	RawData     []byte    `json:"raw_data,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Status      string    `json:"status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	SourceRunID string    `json:"source_run_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	Schedule    string    `json:"schedule,omitempty"`
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
	Type           string    `json:"type"`
	Target         string    `json:"target"`
	Artifact       string    `json:"artifact"`
	Queue          string    `json:"queue,omitempty"`
	Input          []byte    `json:"input,omitempty"`
	Schedule       string    `json:"schedule,omitempty"`
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
	CampaignID   string `json:"campaign_id,omitempty"`
	BatchID      string `json:"batch_id,omitempty"`
	Type         string `json:"type,omitempty"`
	Artifact     string `json:"artifact,omitempty"`
	Queue        string `json:"queue,omitempty"`
	Target       string `json:"target,omitempty"`
	WorkflowID   string `json:"workflow_id,omitempty"`
	LeaseSeconds int    `json:"lease_seconds,omitempty"`
	Schedule     string `json:"schedule,omitempty"`
	MaxRunning   int    `json:"max_running,omitempty"`
}

type SchedulerCapacity struct {
	CampaignID          string    `json:"campaign_id,omitempty"`
	BatchID             string    `json:"batch_id,omitempty"`
	SnapshotKind        string    `json:"snapshot_kind"`
	Queue               string    `json:"queue"`
	Artifact            string    `json:"artifact,omitempty"`
	MinCapacity         int       `json:"min_capacity"`
	MaxCapacity         int       `json:"max_capacity"`
	EffectiveCapacity   int       `json:"effective_capacity"`
	RecommendedCapacity int       `json:"recommended_capacity"`
	Running             int       `json:"running"`
	Pending             int       `json:"pending"`
	RetryWaiting        int       `json:"retry_waiting"`
	StalledRunning      int       `json:"stalled_running"`
	Completed           int       `json:"completed"`
	Failed              int       `json:"failed"`
	Dead                int       `json:"dead"`
	AvgDurationMs       int64     `json:"avg_duration_ms,omitempty"`
	ThroughputPerMin    int       `json:"throughput_per_min,omitempty"`
	StatRequests        int64     `json:"stat_requests,omitempty"`
	StatResults         int64     `json:"stat_results,omitempty"`
	StatErrors          int64     `json:"stat_errors,omitempty"`
	ErrorRatePercent    float64   `json:"error_rate_percent,omitempty"`
	LastDecision        string    `json:"last_decision,omitempty"`
	DecisionReason      string    `json:"decision_reason,omitempty"`
	SnapshotNote        string    `json:"snapshot_note,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type SchedulerCapacityPolicy struct {
	Queue      string `json:"queue"`
	Artifact   string `json:"artifact,omitempty"`
	Min        int    `json:"min"`
	Initial    int    `json:"initial"`
	Max        int    `json:"max"`
	SlowMs     int64  `json:"slow_ms,omitempty"`
	ErrorLimit int    `json:"error_limit_percent,omitempty"`
}

type SchedulerCapacityUpdateRequest struct {
	CampaignID string `json:"campaign_id,omitempty"`
	BatchID    string `json:"batch_id,omitempty"`
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
	Matched int                 `json:"matched"`
	Updated int                 `json:"updated"`
	Batches []WorkItemBulkBatch `json:"batches,omitempty"`
}

type WorkItemBulkBatch struct {
	CampaignID string `json:"campaign_id,omitempty"`
	BatchID    string `json:"batch_id,omitempty"`
}

type WorkItemGroupSummary struct {
	Key                    string `json:"key"`
	Total                  int    `json:"total"`
	Pending                int    `json:"pending"`
	Running                int    `json:"running"`
	StalledRunning         int    `json:"stalled_running,omitempty"`
	NoProgressRunning      int    `json:"no_progress_running,omitempty"`
	Completed              int    `json:"completed"`
	Failed                 int    `json:"failed"`
	RetryWaiting           int    `json:"retry_waiting"`
	Paused                 int    `json:"paused"`
	Cancelled              int    `json:"cancelled"`
	Skipped                int    `json:"skipped"`
	Dead                   int    `json:"dead"`
	Queued                 int    `json:"queued"`
	Done                   int    `json:"done"`
	Error                  int    `json:"error"`
	ProgressPercent        int    `json:"progress_percent"`
	AvgDurationMs          int64  `json:"avg_duration_ms,omitempty"`
	ThroughputPerMin       int    `json:"throughput_per_min,omitempty"`
	ETASeconds             int64  `json:"eta_seconds,omitempty"`
	OldestRunningStartedAt string `json:"oldest_running_started_at,omitempty"`
	OldestRunningHeartbeat string `json:"oldest_running_heartbeat_at,omitempty"`
	NextLeaseExpiresAt     string `json:"next_lease_expires_at,omitempty"`
	LastError              string `json:"last_error,omitempty"`
	LastErrorUpdatedAt     string `json:"last_error_updated_at,omitempty"`
}

type WorkItemProgressSummary struct {
	Total            int                    `json:"total"`
	ByStatus         map[string]int         `json:"by_status"`
	Overall          WorkItemGroupSummary   `json:"overall"`
	ByType           []WorkItemGroupSummary `json:"by_type"`
	ByQueue          []WorkItemGroupSummary `json:"by_queue"`
	ByArtifact       []WorkItemGroupSummary `json:"by_artifact"`
	ByTarget         []WorkItemGroupSummary `json:"by_target,omitempty"`
	GeneratedAt      time.Time              `json:"generated_at"`
	ETASeconds       int64                  `json:"eta_seconds,omitempty"`
	ThroughputPerMin int                    `json:"throughput_per_min,omitempty"`
}

type CampaignRuntimeView struct {
	Campaign            *Campaign                `json:"campaign,omitempty"`
	Phase               string                   `json:"phase"`
	PhaseReason         string                   `json:"phase_reason,omitempty"`
	PhaseBlockingReason string                   `json:"phase_blocking_reason,omitempty"`
	CurrentBottleneck   *RuntimeBottleneck       `json:"current_bottleneck,omitempty"`
	ExecutionPlan       []RuntimePlanItem        `json:"execution_plan,omitempty"`
	OpenPhaseWork       []WorkItemGroupSummary   `json:"open_phase_work,omitempty"`
	RuntimeQueues       []QueueRuntimeState      `json:"runtime_queues,omitempty"`
	BlockedQueues       []QueueRuntimeState      `json:"blocked_queues,omitempty"`
	SlowTargets         []TargetRuntimeState     `json:"slow_targets,omitempty"`
	ArtifactHealth      []ArtifactRuntimeHealth  `json:"artifact_health,omitempty"`
	ProblemArtifacts    []ArtifactRuntimeHealth  `json:"problem_artifacts,omitempty"`
	CapacityDecisions   []SchedulerCapacity      `json:"capacity_decisions,omitempty"`
	CapacityProfiles    []RuntimeCapacityProfile `json:"capacity_profiles,omitempty"`
	RuntimeWarnings     []string                 `json:"runtime_warnings,omitempty"`
	ETA                 ETARuntimeState          `json:"eta"`
	Summary             WorkItemProgressSummary  `json:"summary"`
	RecentPhaseEvents   []CampaignPhaseEvent     `json:"recent_phase_events,omitempty"`
	GeneratedAt         time.Time                `json:"generated_at"`
}

type RuntimeWorkCounts struct {
	Pending           int    `json:"pending"`
	Running           int    `json:"running"`
	Completed         int    `json:"completed"`
	Failed            int    `json:"failed"`
	Dead              int    `json:"dead"`
	RetryWaiting      int    `json:"retry_waiting,omitempty"`
	Paused            int    `json:"paused,omitempty"`
	StalledRunning    int    `json:"stalled_running,omitempty"`
	NoProgressRunning int    `json:"no_progress_running,omitempty"`
	ProgressPercent   int    `json:"progress_percent,omitempty"`
	ETASeconds        int64  `json:"eta_seconds,omitempty"`
	LastError         string `json:"last_error,omitempty"`
}

type RuntimeBottleneck struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
	RuntimeWorkCounts
	Reason   string `json:"reason"`
	Phase    string `json:"phase,omitempty"`
	Queue    string `json:"queue,omitempty"`
	Type     string `json:"type,omitempty"`
	Artifact string `json:"artifact,omitempty"`
	Target   string `json:"target,omitempty"`
}

type RuntimePlanItem struct {
	Type     string `json:"type"`
	Queue    string `json:"queue"`
	Artifact string `json:"artifact"`
	Phase    string `json:"phase"`
	RuntimeWorkCounts
	Allowed        bool   `json:"allowed"`
	State          string `json:"state"`
	Reason         string `json:"reason"`
	NextPhase      string `json:"next_phase,omitempty"`
	BlockingReason string `json:"blocking_reason,omitempty"`
}

type QueueRuntimeState struct {
	Queue string `json:"queue"`
	RuntimeWorkCounts
	Reason string `json:"reason"`
}

type TargetRuntimeState struct {
	Target                 string `json:"target"`
	Total                  int    `json:"total"`
	Queued                 int    `json:"queued"`
	Running                int    `json:"running"`
	StalledRunning         int    `json:"stalled_running,omitempty"`
	Failed                 int    `json:"failed"`
	Dead                   int    `json:"dead"`
	ETASeconds             int64  `json:"eta_seconds,omitempty"`
	OldestRunningStartedAt string `json:"oldest_running_started_at,omitempty"`
	LastError              string `json:"last_error,omitempty"`
	Reason                 string `json:"reason"`
}

type ArtifactRuntimeHealth struct {
	Artifact         string  `json:"artifact"`
	StatRecords      int     `json:"stat_records,omitempty"`
	WorkItemRuns     int     `json:"work_item_runs,omitempty"`
	Requests         int64   `json:"requests,omitempty"`
	Results          int64   `json:"results,omitempty"`
	Errors           int64   `json:"errors,omitempty"`
	ErrorRatePercent float64 `json:"error_rate_percent,omitempty"`
	ThroughputPerMin int64   `json:"throughput_per_min,omitempty"`
	Reason           string  `json:"reason,omitempty"`
}

type RuntimeCapacityProfile struct {
	Queue                      string `json:"queue,omitempty"`
	Artifact                   string `json:"artifact"`
	SchedulerScope             string `json:"scheduler_scope"`
	SchedulerMinCapacity       int    `json:"scheduler_min_capacity,omitempty"`
	SchedulerInitialCapacity   int    `json:"scheduler_initial_capacity,omitempty"`
	SchedulerMaxCapacity       int    `json:"scheduler_max_capacity,omitempty"`
	SchedulerSlowMs            int64  `json:"scheduler_slow_ms,omitempty"`
	SchedulerErrorLimitPercent int    `json:"scheduler_error_limit_percent,omitempty"`
	SchedulerDescription       string `json:"scheduler_description,omitempty"`
	SDKScope                   string `json:"sdk_scope"`
	SDKConfiguredCapacity      int    `json:"sdk_configured_capacity,omitempty"`
	SDKDefaultCapacity         int    `json:"sdk_default_capacity,omitempty"`
	SDKUnit                    string `json:"sdk_unit,omitempty"`
	SDKDescription             string `json:"sdk_description,omitempty"`
	ObservationNote            string `json:"observation_note,omitempty"`
}

type ETARuntimeState struct {
	Seconds    int64  `json:"seconds,omitempty"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type ArtifactStatSummary struct {
	Artifact                string  `json:"artifact"`
	StatRecords             int     `json:"stat_records"`
	WorkItemRuns            int     `json:"work_item_runs"`
	ArtifactRequests        int64   `json:"artifact_requests,omitempty"`
	Targets                 int64   `json:"targets,omitempty"`
	Tasks                   int64   `json:"tasks,omitempty"`
	Requests                int64   `json:"requests,omitempty"`
	Results                 int64   `json:"results,omitempty"`
	Errors                  int64   `json:"errors,omitempty"`
	ErrorScope              string  `json:"error_scope,omitempty"`
	DurationMs              int64   `json:"duration_ms,omitempty"`
	AvgDurationMs           int64   `json:"avg_duration_ms,omitempty"`
	ErrorRatePercent        float64 `json:"error_rate_percent"`
	RequestErrorRatePercent float64 `json:"request_error_rate_percent"`
	ThroughputPerMin        int64   `json:"throughput_per_min,omitempty"`
}

// RawEvent stores artifact output exactly as produced, before any transformation.
type RawEvent struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaign_id,omitempty"`
	Artifact    string    `json:"artifact"`
	TargetID    string    `json:"target_id"`    // normalized target hash, references targets.id
	TargetValue string    `json:"target_value"` // original scan target value
	TargetType  string    `json:"target_type"`  // "cidr", "domain", "ip"
	WorkflowID  string    `json:"workflow_id"`
	Data        []byte    `json:"data"`
	CreatedAt   time.Time `json:"created_at"`
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
	Status     string             `json:"status,omitempty"`
	Path       []EvidencePathStep `json:"path,omitempty"`
}

// EvidencePathStep describes one hop in a knowledge evidence chain.
type EvidencePathStep struct {
	Relation string `json:"relation,omitempty"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}
