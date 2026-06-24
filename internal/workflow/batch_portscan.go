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
	Targets                []string `json:"targets"`
	NowTargets             []string `json:"now_targets,omitempty"`
	CampaignID             string   `json:"campaign_id,omitempty"`
	Ports                  string   `json:"ports"`
	ChunkPrefix            int      `json:"chunk_prefix,omitempty"`
	MaxAttempts            int      `json:"max_attempts,omitempty"`
	RetryDelaySeconds      int      `json:"retry_delay_seconds,omitempty"`
	ActivityTimeoutSeconds int      `json:"activity_timeout_seconds,omitempty"`
	CampaignPhase          string   `json:"campaign_phase,omitempty"`

	RunPlannedDAG           bool `json:"run_planned_dag,omitempty"`
	PlannedDAGMaxIterations int  `json:"planned_dag_max_iterations,omitempty"`
	SprayShardBaseURLs      int  `json:"spray_shard_base_urls,omitempty"`
	SprayShardWords         int  `json:"spray_shard_words,omitempty"`
	NucleiGroupTargets      int  `json:"nuclei_group_targets,omitempty"`
	NucleiGroupTemplates    int  `json:"nuclei_group_templates,omitempty"`
}

type BatchPortScanResult struct {
	Targets        []string `json:"targets"`
	NowTargets     []string `json:"now_targets,omitempty"`
	Ports          string   `json:"ports"`
	ChunkPrefix    int      `json:"chunk_prefix"`
	MaxAttempts    int      `json:"max_attempts"`
	RetryDelay     int      `json:"retry_delay_seconds,omitempty"`
	CampaignPhase  string   `json:"campaign_phase,omitempty"`
	RunPlannedDAG  bool     `json:"run_planned_dag,omitempty"`
	TotalChunks    int      `json:"total_chunks"`
	Completed      int      `json:"completed"`
	Failed         int      `json:"failed"`
	FollowUpTotal  int      `json:"follow_up_total,omitempty"`
	FollowUpFailed int      `json:"follow_up_failed,omitempty"`
	ActionTotal    int      `json:"action_total,omitempty"`
	ActionFailed   int      `json:"action_failed,omitempty"`
}

type batchPortScanChunk struct {
	Target string
	Chunk  string
}

const workItemUpsertBatchSize = 25

// BatchPortScanWorkflow expands many IP/CIDR targets into durable work items
// and hands execution to SchedulerWorkflow.
func BatchPortScanWorkflow(ctx workflow.Context, input BatchPortScanInput) (*BatchPortScanResult, error) {
	input = normalizeBatchPortScanInput(input)

	chunks := buildPortScanChunks(input.Targets, input.ChunkPrefix)
	chunks = schedulePortScanChunks(chunks, input.NowTargets, input.ChunkPrefix)
	result := &BatchPortScanResult{
		Targets:       input.Targets,
		NowTargets:    input.NowTargets,
		Ports:         input.Ports,
		ChunkPrefix:   input.ChunkPrefix,
		MaxAttempts:   input.MaxAttempts,
		RetryDelay:    input.RetryDelaySeconds,
		CampaignPhase: input.CampaignPhase,
		RunPlannedDAG: input.RunPlannedDAG,
		TotalChunks:   len(chunks),
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
		schedule := chunkSchedule(chunk, input.NowTargets, input.ChunkPrefix)
		if shouldRunDNSPreflight(chunk) {
			workItems = append(workItems, dnsPreflightWorkItem(parentID, input, chunk, "", "pending", "", schedule))
			continue
		}
		workItems = append(workItems, portScanChunkWorkItem(parentID, input, chunk, "", "pending", "", schedule))
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

func portScanChunkWorkItem(batchID string, input BatchPortScanInput, chunk batchPortScanChunk, workflowID, status, errorMessage string, schedule string) data.WorkItem {
	itemType := data.WorkItemTypePortscanChunk
	return data.WorkItem{
		ID:          portScanChunkWorkItemID(batchID, chunk.Chunk),
		CampaignID:  input.CampaignID,
		BatchID:     batchID,
		Type:        itemType,
		Target:      chunk.Chunk,
		Artifact:    data.WorkItemArtifactForType(itemType),
		Queue:       data.WorkItemQueueForType(itemType),
		Input:       mustMarshal(map[string]interface{}{"ip": chunk.Chunk, "ports": input.Ports, "source_target": chunk.Target}),
		Schedule:    data.NormalizeSchedule(schedule),
		Status:      status,
		MaxAttempts: input.MaxAttempts,
		WorkflowID:  workflowID,
		Error:       errorMessage,
	}
}

func dnsPreflightWorkItem(batchID string, input BatchPortScanInput, chunk batchPortScanChunk, workflowID, status, errorMessage string, schedule string) data.WorkItem {
	itemType := data.WorkItemTypeDNSPreflight
	return data.WorkItem{
		ID:          dnsPreflightWorkItemID(batchID, chunk.Chunk),
		CampaignID:  input.CampaignID,
		BatchID:     batchID,
		Type:        itemType,
		Target:      chunk.Chunk,
		Artifact:    data.WorkItemArtifactForType(itemType),
		Queue:       data.WorkItemQueueForType(itemType),
		Input:       mustMarshal(map[string]interface{}{"target": chunk.Chunk, "source_target": chunk.Target}),
		Schedule:    data.NormalizeSchedule(schedule),
		Status:      status,
		MaxAttempts: input.MaxAttempts,
		WorkflowID:  workflowID,
		Error:       errorMessage,
	}
}

func portScanChunkWorkItemID(batchID, chunk string) string {
	return data.GenerateID("work_item", batchID, data.WorkItemTypePortscanChunk, chunk)
}

func dnsPreflightWorkItemID(batchID, chunk string) string {
	return data.GenerateID("work_item", batchID, data.WorkItemTypeDNSPreflight, chunk)
}

func plannedDAGFollowUpWorkItemID(batchID, chunk string, iteration int) string {
	if iteration <= 0 {
		iteration = 1
	}
	return data.GenerateID("work_item", batchID, data.WorkItemTypePlannedDAGFollowUp, chunk, fmt.Sprintf("%d", iteration))
}

func shouldRunDNSPreflight(chunk batchPortScanChunk) bool {
	return !workflowTargetIsCIDR(chunk.Chunk)
}

func chunkSchedule(chunk batchPortScanChunk, nowTargets []string, chunkPrefix int) string {
	if len(nowTargets) == 0 {
		return data.ScheduleBatch
	}
	for _, target := range nowTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if target == chunk.Target || target == chunk.Chunk {
			return data.ScheduleNow
		}
		for _, nowChunk := range splitCIDRToPrefix(target, chunkPrefix) {
			if nowChunk == chunk.Chunk {
				return data.ScheduleNow
			}
		}
	}
	return data.ScheduleBatch
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

func schedulePortScanChunks(chunks []batchPortScanChunk, nowTargets []string, chunkPrefix int) []batchPortScanChunk {
	if len(chunks) == 0 || len(nowTargets) == 0 {
		return chunks
	}
	now := make(map[string]bool)
	for _, target := range nowTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		now[target] = true
		for _, chunk := range splitCIDRToPrefix(target, chunkPrefix) {
			now[chunk] = true
		}
	}
	if len(now) == 0 {
		return chunks
	}
	out := make([]batchPortScanChunk, 0, len(chunks))
	for _, chunk := range chunks {
		if now[chunk.Chunk] || now[chunk.Target] {
			out = append(out, chunk)
		}
	}
	for _, chunk := range chunks {
		if now[chunk.Chunk] || now[chunk.Target] {
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
