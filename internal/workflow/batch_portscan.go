package workflow

import (
	"fmt"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type BatchPortScanInput struct {
	Targets                []string       `json:"targets"`
	PriorityTargets        []string       `json:"priority_targets,omitempty"`
	CampaignID             string         `json:"campaign_id,omitempty"`
	Ports                  string         `json:"ports"`
	MaxConcurrency         int            `json:"max_concurrency,omitempty"`
	ChunkPrefix            int            `json:"chunk_prefix,omitempty"`
	MaxAttempts            int            `json:"max_attempts,omitempty"`
	RetryDelaySeconds      int            `json:"retry_delay_seconds,omitempty"`
	ActivityTimeoutSeconds int            `json:"activity_timeout_seconds,omitempty"`
	QueueLimits            map[string]int `json:"queue_limits,omitempty"`
	ResourceLimits         ResourceLimits `json:"resource_limits,omitempty"`

	RunPlannedDAG           bool `json:"run_planned_dag,omitempty"`
	PlannedDAGConcurrency   int  `json:"planned_dag_concurrency,omitempty"`
	PlannedDAGMaxIterations int  `json:"planned_dag_max_iterations,omitempty"`
	PlannedDAGContinue      bool `json:"planned_dag_continue_on_failure,omitempty"`
	SprayShardBaseURLs      int  `json:"spray_shard_base_urls,omitempty"`
	SprayShardWords         int  `json:"spray_shard_words,omitempty"`
	NucleiGroupTargets      int  `json:"nuclei_group_targets,omitempty"`
	NucleiGroupTemplates    int  `json:"nuclei_group_templates,omitempty"`
}

type ResourceLimits struct {
	Queue              map[string]int `json:"queue,omitempty"`
	Artifact           map[string]int `json:"artifact,omitempty"`
	MaxRunningCampaign int            `json:"max_running_campaign,omitempty"`
	MaxRunningTarget   int            `json:"max_running_target,omitempty"`
}

type BatchPortScanResult struct {
	Targets         []string                   `json:"targets"`
	PriorityTargets []string                   `json:"priority_targets,omitempty"`
	Ports           string                     `json:"ports"`
	MaxConcurrency  int                        `json:"max_concurrency"`
	ChunkPrefix     int                        `json:"chunk_prefix"`
	MaxAttempts     int                        `json:"max_attempts"`
	RetryDelay      int                        `json:"retry_delay_seconds,omitempty"`
	RunPlannedDAG   bool                       `json:"run_planned_dag,omitempty"`
	TotalChunks     int                        `json:"total_chunks"`
	Completed       int                        `json:"completed"`
	Failed          int                        `json:"failed"`
	FollowUpTotal   int                        `json:"follow_up_total,omitempty"`
	FollowUpFailed  int                        `json:"follow_up_failed,omitempty"`
	ActionTotal     int                        `json:"action_total,omitempty"`
	ActionFailed    int                        `json:"action_failed,omitempty"`
	Chunks          []BatchPortScanChunkResult `json:"chunks,omitempty"`
}

type BatchPortScanChunkResult struct {
	Target             string `json:"target"`
	Chunk              string `json:"chunk"`
	WorkflowID         string `json:"workflow_id,omitempty"`
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
	FollowUpWorkflowID string `json:"follow_up_workflow_id,omitempty"`
	FollowUpCompleted  int    `json:"follow_up_completed,omitempty"`
	FollowUpFailed     int    `json:"follow_up_failed,omitempty"`
	FollowUpSkipped    int    `json:"follow_up_skipped,omitempty"`
	FollowUpError      string `json:"follow_up_error,omitempty"`
}

type batchPortScanChunk struct {
	Target string
	Chunk  string
}

const workItemUpsertBatchSize = 25

// BatchPortScanWorkflow expands many IP/CIDR targets into scan chunks and runs
// gogo-only child workflows with bounded concurrency.
func BatchPortScanWorkflow(ctx workflow.Context, input BatchPortScanInput) (*BatchPortScanResult, error) {
	input = normalizeBatchPortScanInput(input)

	chunks := buildPortScanChunks(input.Targets, input.ChunkPrefix)
	chunks = prioritizePortScanChunks(chunks, input.PriorityTargets, input.ChunkPrefix)
	result := &BatchPortScanResult{
		Targets:         input.Targets,
		PriorityTargets: input.PriorityTargets,
		Ports:           input.Ports,
		MaxConcurrency:  input.MaxConcurrency,
		ChunkPrefix:     input.ChunkPrefix,
		MaxAttempts:     input.MaxAttempts,
		RetryDelay:      input.RetryDelaySeconds,
		RunPlannedDAG:   input.RunPlannedDAG,
		TotalChunks:     len(chunks),
	}
	parentID := workflow.GetInfo(ctx).WorkflowExecution.ID
	if len(chunks) == 0 {
		stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 30 * time.Second,
			RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
		})
		if err := upsertPortScanBatchRun(stateCtx, parentID, input, result, "completed"); err != nil {
			return result, err
		}
		return result, nil
	}

	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	if err := upsertPortScanBatchRun(stateCtx, parentID, input, result, "running"); err != nil {
		return result, err
	}
	workItems := make([]data.WorkItem, 0, len(chunks))
	for _, chunk := range chunks {
		if err := upsertPortScanBatchChunk(stateCtx, parentID, chunk, "", "pending", ""); err != nil {
			return result, err
		}
		workItems = append(workItems, portScanChunkWorkItem(parentID, input, chunk, "", "pending", "", chunkPriority(chunk, input.PriorityTargets, input.ChunkPrefix)))
	}
	if err := upsertBatchWorkItems(stateCtx, workItems); err != nil {
		return result, err
	}

	schedulerID := fmt.Sprintf("%s-scheduler", parentID)
	childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID:          schedulerID,
		WorkflowTaskTimeout: ControlWorkflowTaskTimeout,
	})
	var schedulerResult SchedulerWorkflowResult
	if err := workflow.ExecuteChildWorkflow(childCtx, SchedulerWorkflow, SchedulerWorkflowInput{
		BatchID:     parentID,
		BatchInput:  input,
		TotalChunks: len(chunks),
	}).Get(childCtx, &schedulerResult); err != nil {
		return result, err
	}

	result.Completed = schedulerResult.PortScanDone
	result.Failed = schedulerResult.PortScanFailed
	result.FollowUpTotal = schedulerResult.FollowUpTotal
	result.FollowUpFailed = schedulerResult.FollowUpFailed
	result.ActionTotal = schedulerResult.ActionTotal
	result.ActionFailed = schedulerResult.ActionFailed
	return result, nil
}

func followUpResultCompleted(result *PlannedDAGWorkflowResult) int {
	if result == nil {
		return 0
	}
	total := 0
	for _, run := range result.Runs {
		total += run.Completed
	}
	return total
}

func followUpResultFailed(result *PlannedDAGWorkflowResult) int {
	if result == nil {
		return 0
	}
	total := 0
	for _, run := range result.Runs {
		total += run.Failed
	}
	return total
}

func followUpResultSkipped(result *PlannedDAGWorkflowResult) int {
	if result == nil {
		return 0
	}
	total := 0
	for _, run := range result.Runs {
		total += run.Skipped
	}
	return total
}

func upsertPortScanBatchRun(ctx workflow.Context, batchID string, input BatchPortScanInput, result *BatchPortScanResult, status string) error {
	return workflow.ExecuteActivity(ctx, planner.UpsertBatchRunActivityName, data.BatchRun{
		ID:          batchID,
		CampaignID:  input.CampaignID,
		WorkflowID:  batchID,
		Type:        "batch_portscan",
		Target:      strings.Join(input.Targets, "\n"),
		Ports:       input.Ports,
		Status:      status,
		TotalChunks: result.TotalChunks,
		Completed:   result.Completed,
		Failed:      result.Failed,
	}).Get(ctx, nil)
}

func upsertPortScanBatchChunk(ctx workflow.Context, batchID string, chunk batchPortScanChunk, workflowID, status, errorMessage string) error {
	return workflow.ExecuteActivity(ctx, planner.UpsertBatchChunkActivityName, data.BatchChunk{
		ID:         data.GenerateID("batch_chunk", batchID, chunk.Chunk),
		BatchID:    batchID,
		Target:     chunk.Target,
		Chunk:      chunk.Chunk,
		WorkflowID: workflowID,
		Status:     status,
		Error:      errorMessage,
	}).Get(ctx, nil)
}

func upsertBatchWorkItem(ctx workflow.Context, item data.WorkItem) error {
	return workflow.ExecuteActivity(ctx, planner.UpsertWorkItemActivityName, item).Get(ctx, nil)
}

func upsertBatchWorkItems(ctx workflow.Context, items []data.WorkItem) error {
	for _, chunk := range chunkWorkItems(items, workItemUpsertBatchSize) {
		if err := workflow.ExecuteActivity(ctx, planner.UpsertWorkItemsActivityName, chunk).Get(ctx, nil); err != nil {
			return err
		}
	}
	return nil
}

func chunkWorkItems(items []data.WorkItem, size int) [][]data.WorkItem {
	if len(items) == 0 {
		return nil
	}
	if size <= 0 || size >= len(items) {
		return [][]data.WorkItem{items}
	}
	chunks := make([][]data.WorkItem, 0, (len(items)+size-1)/size)
	for start := 0; start < len(items); start += size {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[start:end])
	}
	return chunks
}

func setBatchWorkItemStatus(ctx workflow.Context, id, status, workflowID, errorMessage string, incrementAttempt bool) error {
	return setBatchWorkItemStatusWithLease(ctx, id, status, workflowID, errorMessage, incrementAttempt, 0)
}

func setBatchWorkItemStatusWithLease(ctx workflow.Context, id, status, workflowID, errorMessage string, incrementAttempt bool, leaseSeconds int) error {
	return workflow.ExecuteActivity(ctx, planner.SetWorkItemStatusActivityName, planner.WorkItemStatusUpdate{
		ID:               id,
		Status:           status,
		WorkflowID:       workflowID,
		Error:            errorMessage,
		IncrementAttempt: incrementAttempt,
		LeaseSeconds:     leaseSeconds,
	}).Get(ctx, nil)
}

func campaignPaused(ctx workflow.Context, campaignID string) (bool, error) {
	if campaignID == "" {
		return false, nil
	}
	var status string
	if err := workflow.ExecuteActivity(ctx, planner.GetCampaignStatusActivityName, campaignID).Get(ctx, &status); err != nil {
		return false, err
	}
	return status == "paused", nil
}

func portScanChunkWorkItem(batchID string, input BatchPortScanInput, chunk batchPortScanChunk, workflowID, status, errorMessage string, priority int) data.WorkItem {
	return data.WorkItem{
		ID:          portScanChunkWorkItemID(batchID, chunk.Chunk),
		CampaignID:  input.CampaignID,
		BatchID:     batchID,
		Type:        "portscan_chunk",
		Target:      chunk.Chunk,
		Artifact:    "gogo",
		Queue:       "portscan",
		Input:       mustMarshal(map[string]interface{}{"ip": chunk.Chunk, "ports": input.Ports, "source_target": chunk.Target}),
		Priority:    priority,
		Status:      status,
		MaxAttempts: input.MaxAttempts,
		WorkflowID:  workflowID,
		Error:       errorMessage,
	}
}

func portScanChunkWorkItemID(batchID, chunk string) string {
	return data.GenerateID("work_item", batchID, "portscan_chunk", chunk)
}

func plannedDAGFollowUpWorkItemID(batchID, chunk string, iteration int) string {
	if iteration <= 0 {
		iteration = 1
	}
	return data.GenerateID("work_item", batchID, "planned_dag_followup", chunk, fmt.Sprintf("%d", iteration))
}

func chunkPriority(chunk batchPortScanChunk, priorityTargets []string, chunkPrefix int) int {
	if len(priorityTargets) == 0 {
		return 0
	}
	for _, target := range priorityTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if target == chunk.Target || target == chunk.Chunk {
			return 100
		}
		for _, priorityChunk := range splitCIDRToPrefix(target, chunkPrefix) {
			if priorityChunk == chunk.Chunk {
				return 100
			}
		}
	}
	return 0
}

func buildPortScanChunks(targets []string, chunkPrefix int) []batchPortScanChunk {
	seen := make(map[string]bool)
	var chunks []batchPortScanChunk
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for _, chunk := range splitCIDRToPrefix(target, chunkPrefix) {
			if seen[chunk] {
				continue
			}
			seen[chunk] = true
			chunks = append(chunks, batchPortScanChunk{Target: target, Chunk: chunk})
		}
	}
	return chunks
}

func prioritizePortScanChunks(chunks []batchPortScanChunk, priorityTargets []string, chunkPrefix int) []batchPortScanChunk {
	if len(chunks) == 0 || len(priorityTargets) == 0 {
		return chunks
	}
	priority := make(map[string]bool)
	for _, target := range priorityTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		priority[target] = true
		for _, chunk := range splitCIDRToPrefix(target, chunkPrefix) {
			priority[chunk] = true
		}
	}
	if len(priority) == 0 {
		return chunks
	}
	out := make([]batchPortScanChunk, 0, len(chunks))
	for _, chunk := range chunks {
		if priority[chunk.Chunk] || priority[chunk.Target] {
			out = append(out, chunk)
		}
	}
	for _, chunk := range chunks {
		if priority[chunk.Chunk] || priority[chunk.Target] {
			continue
		}
		out = append(out, chunk)
	}
	return out
}

func safeWorkflowIDPart(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
