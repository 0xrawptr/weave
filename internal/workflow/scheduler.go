package workflow

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/admission"
	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"github.com/0xrawptr/weave/internal/recovery"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type SchedulerWorkflowInput struct {
	BatchID         string             `json:"batch_id"`
	BatchInput      BatchPortScanInput `json:"batch_input"`
	TotalChunks     int                `json:"total_chunks"`
	ContinueAfter   int                `json:"continue_after,omitempty"`
	ContinuedRuns   int                `json:"continued_runs,omitempty"`
	MaxContinueRuns int                `json:"max_continue_runs,omitempty"`
}

type SchedulerWorkflowResult struct {
	BatchID          string `json:"batch_id"`
	Status           string `json:"status"`
	PreflightTotal   int    `json:"preflight_total,omitempty"`
	PreflightDone    int    `json:"preflight_done,omitempty"`
	PreflightFailed  int    `json:"preflight_failed,omitempty"`
	PreflightPending int    `json:"preflight_pending,omitempty"`
	PreflightRunning int    `json:"preflight_running,omitempty"`
	PortScanTotal    int    `json:"portscan_total"`
	PortScanDone     int    `json:"portscan_done"`
	PortScanFailed   int    `json:"portscan_failed"`
	PortScanPending  int    `json:"portscan_pending,omitempty"`
	PortScanRunning  int    `json:"portscan_running,omitempty"`
	FollowUpTotal    int    `json:"follow_up_total,omitempty"`
	FollowUpDone     int    `json:"follow_up_done,omitempty"`
	FollowUpFailed   int    `json:"follow_up_failed,omitempty"`
	FollowUpPending  int    `json:"follow_up_pending,omitempty"`
	FollowUpRunning  int    `json:"follow_up_running,omitempty"`
	ActionTotal      int    `json:"action_total,omitempty"`
	ActionDone       int    `json:"action_done,omitempty"`
	ActionFailed     int    `json:"action_failed,omitempty"`
	ActionPending    int    `json:"action_pending,omitempty"`
	ActionRunning    int    `json:"action_running,omitempty"`
	ContinuedRuns    int    `json:"continued_runs,omitempty"`
	ProcessedThisRun int    `json:"processed_this_run,omitempty"`
}

type schedulerWorkItemInput struct {
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
	RunIf         *planner.ConditionRequest `json:"run_if,omitempty"`
	Iteration     int                       `json:"iteration,omitempty"`
	MaxIterations int                       `json:"max_iterations,omitempty"`
	ShardIndex    int                       `json:"shard_index,omitempty"`
}

type ScheduledWorkItemWorkflowInput struct {
	SchedulerInput SchedulerWorkflowInput `json:"scheduler_input"`
	Item           data.WorkItem          `json:"item"`
	WorkflowID     string                 `json:"workflow_id"`
}

const schedulerMaxDispatchPerRun = 10
const schedulerWakeupSignalName = "scheduler.wakeup"
const schedulerRunningLeaseSeconds = 90
const schedulerIdleWakeupInterval = 10 * time.Second

func SchedulerWorkflow(ctx workflow.Context, input SchedulerWorkflowInput) (*SchedulerWorkflowResult, error) {
	input.BatchInput = normalizeBatchPortScanInput(input.BatchInput)
	if input.BatchID == "" {
		input.BatchID = workflow.GetInfo(ctx).WorkflowExecution.ID
	}
	if input.ContinueAfter <= 0 {
		input.ContinueAfter = schedulerMaxDispatchPerRun
	}
	if input.ContinueAfter > schedulerMaxDispatchPerRun {
		input.ContinueAfter = schedulerMaxDispatchPerRun
	}
	if input.MaxContinueRuns <= 0 {
		input.MaxContinueRuns = 10000
	}

	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultStateActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	result := &SchedulerWorkflowResult{BatchID: input.BatchID, ContinuedRuns: input.ContinuedRuns}
	if err := recoverScheduledWorkItems(stateCtx, input); err != nil {
		return result, err
	}

	processed, paused, err := schedulePipelineWorkItems(ctx, stateCtx, input)
	result.ProcessedThisRun += processed
	if err != nil {
		return result, err
	}
	if paused {
		result.Status = "paused"
		if summaryErr := loadSchedulerSummary(stateCtx, input, result); summaryErr != nil {
			return result, summaryErr
		}
		if updateErr := finalizeScheduledBatch(stateCtx, input, result); updateErr != nil {
			return result, updateErr
		}
		return result, nil
	}

	if err := loadSchedulerSummary(stateCtx, input, result); err != nil {
		return result, err
	}
	result.Status = scheduledBatchStatus(result)
	if err := finalizeScheduledBatch(stateCtx, input, result); err != nil {
		return result, err
	}
	if result.Status == "running" && shouldContinueScheduler(input, result.ProcessedThisRun) {
		return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
	}
	if result.Status == "running" && input.ContinuedRuns < input.MaxContinueRuns {
		if err := waitForSchedulerWakeup(ctx, input); err != nil {
			return result, err
		}
		return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
	}
	return result, nil
}

func waitForSchedulerWakeup(ctx workflow.Context, input SchedulerWorkflowInput) error {
	signalCh := workflow.GetSignalChannel(ctx, schedulerWakeupSignalName)
	selector := workflow.NewSelector(ctx)
	selector.AddReceive(signalCh, func(c workflow.ReceiveChannel, more bool) {
		var payload interface{}
		c.Receive(ctx, &payload)
	})
	selector.AddFuture(workflow.NewTimer(ctx, schedulerIdleWakeupInterval), func(workflow.Future) {})
	selector.Select(ctx)
	return nil
}

const (
	CampaignPhaseAuto         = data.CampaignPhaseAuto
	CampaignPhaseBootstrap    = data.CampaignPhaseBootstrap
	CampaignPhaseDiscovery    = data.CampaignPhaseDiscovery
	CampaignPhaseExpansion    = data.CampaignPhaseExpansion
	CampaignPhaseVerification = data.CampaignPhaseVerification
	CampaignPhaseSteady       = data.CampaignPhaseSteady
)

type schedulerPhasePlan struct {
	Phase     string
	ItemTypes []string
	NowOnly   bool
}

type schedulerCapacityMap map[string]int

func schedulerPhasePlanFor(phase string) schedulerPhasePlan {
	normalized := NormalizeCampaignPhase(phase)
	if normalized == CampaignPhaseAuto {
		normalized = CampaignPhaseDiscovery
	}
	itemTypes, nowOnly := data.WorkItemTypesForPhase(normalized)
	return schedulerPhasePlan{Phase: normalized, ItemTypes: itemTypes, NowOnly: nowOnly}
}

func scheduledActionItemTypes() []string {
	return []string{data.WorkItemTypeNucleiGroup, data.WorkItemTypeFingersAction, data.WorkItemTypeSprayShard}
}

func schedulePipelineWorkItems(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput) (int, bool, error) {
	if paused, err := campaignPaused(stateCtx, input.BatchInput.CampaignID); err != nil {
		return 0, false, err
	} else if paused {
		return 0, true, nil
	}
	processed := 0
	for processed < input.ContinueAfter {
		snapshot, err := loadSchedulerSnapshot(stateCtx, input)
		if err != nil {
			return processed, false, err
		}
		phase, err := resolveAndPersistSchedulerCampaignPhaseFromSnapshot(stateCtx, input, snapshot)
		if err != nil {
			return processed, false, err
		}
		plan := schedulerPhasePlanFor(phase)
		capacity, err := updateSchedulerCapacity(stateCtx, input)
		if err != nil {
			return processed, false, err
		}
		madeProgress := 0
		started, err := dispatchScheduleStage(ctx, stateCtx, input, plan, capacity, data.ScheduleNow, input.ContinueAfter-processed)
		if err != nil {
			return processed, false, err
		}
		madeProgress += started
		processed += started
		if processed >= input.ContinueAfter {
			break
		}

		started, err = dispatchScheduleStage(ctx, stateCtx, input, plan, capacity, data.ScheduleBatch, input.ContinueAfter-processed)
		if err != nil {
			return processed, false, err
		}
		madeProgress += started
		processed += started

		if madeProgress == 0 {
			return processed, false, nil
		}
	}
	return processed, false, nil
}

func dispatchScheduleStage(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, plan schedulerPhasePlan, capacity schedulerCapacityMap, schedule string, remaining int) (int, error) {
	if remaining <= 0 {
		return 0, nil
	}
	if plan.NowOnly && data.NormalizeSchedule(schedule) != data.ScheduleNow {
		return 0, nil
	}
	processed := 0
	for processed < remaining {
		madeProgress := 0
		for _, itemType := range plan.ItemTypes {
			if !input.BatchInput.RunPlannedDAG && plannerPhaseItemType(itemType) {
				continue
			}
			started, err := dispatchPhaseWorkItems(ctx, stateCtx, input, itemType, capacity, schedule, remaining-processed)
			if err != nil {
				return processed, err
			}
			madeProgress += started
			processed += started
			if processed >= remaining {
				break
			}
		}

		if madeProgress == 0 {
			break
		}
	}
	return processed, nil
}

func plannerPhaseItemType(itemType string) bool {
	def, ok := data.WorkItemDefinitionForType(itemType)
	return ok && def.Planner
}

func dispatchPhaseWorkItems(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, itemType string, capacity schedulerCapacityMap, schedule string, remaining int) (int, error) {
	switch itemType {
	case "dns_preflight":
		queue := "dns"
		return dispatchScheduledWorkItems(ctx, stateCtx, input, itemType, schedule, schedulerPipelineBurst(capacity, queue, remaining), schedulerQueueCapacity(capacity, queue), startScheduledDNSPreflightWorkItem)
	case "portscan_chunk":
		queue := "portscan"
		return dispatchScheduledWorkItems(ctx, stateCtx, input, itemType, schedule, schedulerPipelineBurst(capacity, queue, remaining), schedulerQueueCapacity(capacity, queue), startScheduledPortScanWorkItem)
	case "planned_dag_followup":
		queue := "planner"
		return dispatchScheduledWorkItems(ctx, stateCtx, input, itemType, schedule, schedulerPipelineBurst(capacity, queue, remaining), schedulerQueueCapacity(capacity, queue), startScheduledPlannedDAGWorkItem)
	case "fingers_action", "spray_shard", "nuclei_group":
		queue := schedulerQueueForType(itemType)
		return dispatchScheduledWorkItems(ctx, stateCtx, input, itemType, schedule, schedulerPipelineBurst(capacity, queue, remaining), schedulerQueueCapacity(capacity, queue), startScheduledArtifactActionWorkItem)
	default:
		return 0, nil
	}
}

func resolveAndPersistSchedulerCampaignPhaseFromSnapshot(ctx workflow.Context, input SchedulerWorkflowInput, snapshot data.WorkItemProgressSummary) (string, error) {
	desired, reason := desiredSchedulerCampaignPhaseFromSnapshot(input, snapshot)
	if input.BatchInput.CampaignID == "" {
		return desired, nil
	}
	phase := NormalizeCampaignPhase(input.BatchInput.CampaignPhase)
	if phase != CampaignPhaseAuto {
		reason = "manual phase override"
	}
	return updateCampaignPhase(ctx, input, desired, reason)
}

func desiredSchedulerCampaignPhaseFromSnapshot(input SchedulerWorkflowInput, snapshot data.WorkItemProgressSummary) (string, string) {
	phase := NormalizeCampaignPhase(input.BatchInput.CampaignPhase)
	if phase != CampaignPhaseAuto {
		return phase, "manual phase override"
	}
	derived := data.InferCampaignPhaseFromSummary(snapshot)
	return derived, campaignPhaseReason(derived)
}

func campaignPhaseReason(phase string) string {
	switch phase {
	case CampaignPhaseBootstrap:
		return "dns preflight work remains open"
	case CampaignPhaseDiscovery:
		return "discovery work remains open"
	case CampaignPhaseExpansion:
		return "expansion work remains open"
	case CampaignPhaseVerification:
		return "verification work remains open"
	case CampaignPhaseSteady:
		return "no batch backlog remains; waiting for now-lane feedback"
	default:
		return "campaign phase resolved"
	}
}

func updateCampaignPhase(ctx workflow.Context, input SchedulerWorkflowInput, phase, reason string) (string, error) {
	var campaign data.Campaign
	err := workflow.ExecuteActivity(ctx, planner.UpdateCampaignPhaseActivityName, planner.CampaignPhaseUpdate{
		CampaignID: input.BatchInput.CampaignID,
		BatchID:    input.BatchID,
		Phase:      phase,
		Reason:     reason,
	}).Get(ctx, &campaign)
	if err != nil {
		return "", err
	}
	return NormalizeCampaignPhase(campaign.Phase), nil
}

func openWorkItems(summary schedulerWorkItemSummary) int {
	return summary.ByStatus["pending"] +
		summary.ByStatus["running"] +
		summary.ByStatus["retry_waiting"] +
		summary.ByStatus["paused"]
}

func NormalizeCampaignPhase(phase string) string {
	return data.NormalizeCampaignPhase(phase)
}

func dispatchScheduledWorkItems(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, itemType, schedule string, maxStarts, maxRunning int, start func(workflow.Context, workflow.Context, SchedulerWorkflowInput, data.WorkItem) error) (int, error) {
	if maxStarts <= 0 {
		return 0, nil
	}
	started := 0
	for started < maxStarts {
		item, err := claimScheduledWorkItem(stateCtx, input, itemType, schedule, maxRunning)
		if err != nil {
			return started, err
		}
		if item.ID == "" {
			break
		}
		if err := start(ctx, stateCtx, input, item); err != nil {
			return started, err
		}
		started++
	}
	return started, nil
}

func schedulerQueueCapacity(capacity schedulerCapacityMap, queue string) int {
	limit := capacity[queue]
	if limit <= 0 {
		return 1
	}
	return limit
}

func schedulerPipelineBurst(capacity schedulerCapacityMap, queue string, remaining int) int {
	if remaining <= 0 {
		return 0
	}
	limit := schedulerQueueCapacity(capacity, queue)
	if limit > remaining {
		return remaining
	}
	return limit
}

func startScheduledPortScanWorkItem(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem) error {
	childID := artifactWorkItemChildWorkflowID(input.BatchID, item.Type, item.Target, item.ID, item.Attempts)
	return startScheduledWorkItemChild(ctx, stateCtx, input, item, childID, ScheduledArtifactWorkItemWorkflow)
}

func startScheduledDNSPreflightWorkItem(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem) error {
	childID := artifactWorkItemChildWorkflowID(input.BatchID, item.Type, item.Target, item.ID, item.Attempts)
	return startScheduledWorkItemChild(ctx, stateCtx, input, item, childID, ScheduledDNSPreflightWorkItemWorkflow)
}

func startScheduledPlannedDAGWorkItem(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem) error {
	childID := artifactWorkItemChildWorkflowID(input.BatchID, item.Type, item.Target, item.ID, item.Attempts)
	return startScheduledWorkItemChild(ctx, stateCtx, input, item, childID, ScheduledPlannedDAGWorkItemWorkflow)
}

func startScheduledArtifactActionWorkItem(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem) error {
	itemInput := parseSchedulerWorkItemInput(item)
	actionTarget := itemInput.Target
	if actionTarget == "" {
		actionTarget = item.Target
	}
	childID := artifactWorkItemChildWorkflowID(input.BatchID, item.Type, actionTarget, item.ID, item.Attempts)
	return startScheduledWorkItemChild(ctx, stateCtx, input, item, childID, ScheduledArtifactWorkItemWorkflow)
}

func startScheduledWorkItemChild(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem, childID string, workflowFunc interface{}) error {
	return startScheduledWorkItemsChild(ctx, stateCtx, input, []data.WorkItem{item}, childID, workflowFunc, ScheduledWorkItemWorkflowInput{
		SchedulerInput: input,
		Item:           item,
		WorkflowID:     childID,
	})
}

func startScheduledWorkItemsChild(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, items []data.WorkItem, childID string, workflowFunc interface{}, childInput interface{}) error {
	if len(items) == 0 {
		return nil
	}
	for _, item := range items {
		if err := setBatchWorkItemStatusWithLease(stateCtx, item.ID, data.WorkItemStatusRunning, childID, "", false, schedulerRunningLeaseSeconds); err != nil {
			return err
		}
	}
	childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID:          childID,
		ParentClosePolicy:   enumspb.PARENT_CLOSE_POLICY_ABANDON,
		WorkflowTaskTimeout: ControlWorkflowTaskTimeout,
	})
	future := workflow.ExecuteChildWorkflow(childCtx, workflowFunc, childInput)
	if err := future.GetChildWorkflowExecution().Get(ctx, nil); err != nil {
		if childWorkflowAlreadyStarted(err) {
			return nil
		}
		for _, item := range items {
			if updateErr := setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), childID, err.Error(), false); updateErr != nil {
				return updateErr
			}
		}
		return err
	}
	return nil
}

func childWorkflowAlreadyStarted(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "child workflow execution already started") ||
		strings.Contains(value, "workflow execution already started") ||
		strings.Contains(value, "already started")
}

func signalSchedulerWakeup(ctx workflow.Context, input SchedulerWorkflowInput, reason string) {
	if input.BatchID == "" {
		return
	}
	schedulerID := fmt.Sprintf("%s-scheduler", input.BatchID)
	_ = workflow.SignalExternalWorkflow(ctx, schedulerID, "", schedulerWakeupSignalName, map[string]interface{}{
		"batch_id": input.BatchID,
		"reason":   reason,
	}).Get(ctx, nil)
}

func runScheduledPortScanWorkItem(ctx, stateCtx workflow.Context, schedulerInput SchedulerWorkflowInput, item data.WorkItem, workflowID string) error {
	itemInput := parseSchedulerWorkItemInput(item)
	sourceTarget := itemInput.SourceTarget
	if sourceTarget == "" {
		sourceTarget = item.Target
	}
	if err := upsertPortScanBatchChunk(stateCtx, schedulerInput.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: item.Target}, workflowID, "running", ""); err != nil {
		return err
	}

	gogoCtx := artifactActivityContext(ctx, "gogo", schedulerInput.BatchInput.ActivityTimeoutSeconds)
	var gogoResult artifact.ActivityResult
	err := executeArtifactActivity(gogoCtx, "gogo", artifact.Input{
		Target:                item.Target,
		CampaignID:            schedulerInput.BatchInput.CampaignID,
		WorkItemID:            item.ID,
		WorkflowID:            workflowID,
		HeartbeatLeaseSeconds: schedulerRunningLeaseSeconds,
		Data: mustMarshal(map[string]interface{}{
			"ip":            item.Target,
			"ports":         schedulerInput.BatchInput.Ports,
			"source_target": sourceTarget,
		}),
	}, &gogoResult)
	if err == nil && !gogoResult.Success {
		if gogoResult.Error != "" {
			err = temporal.NewApplicationError(gogoResult.Error, "gogo_failed")
		} else {
			err = temporal.NewApplicationError("gogo scan failed", "gogo_failed")
		}
	}
	if err != nil {
		if updateErr := upsertPortScanBatchChunk(stateCtx, schedulerInput.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: item.Target}, workflowID, "failed", err.Error()); updateErr != nil {
			return updateErr
		}
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
	}
	if err := upsertPortScanBatchChunk(stateCtx, schedulerInput.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: item.Target}, workflowID, "completed", ""); err != nil {
		return err
	}
	if err := setBatchWorkItemStatus(stateCtx, item.ID, "completed", workflowID, "", false); err != nil {
		return err
	}
	if !schedulerInput.BatchInput.RunPlannedDAG {
		return nil
	}
	signal, err := portScanChunkPlannerSignal(stateCtx, schedulerInput, item.Target)
	if err != nil {
		return err
	}
	if !signal.HasAssets {
		return nil
	}
	return upsertBatchWorkItem(stateCtx, plannedDAGFollowUpWorkItemFromScheduler(schedulerInput, item, signal.Schedule))
}

func ScheduledDNSPreflightWorkItemWorkflow(ctx workflow.Context, input ScheduledWorkItemWorkflowInput) error {
	schedulerInput := input.SchedulerInput
	schedulerInput.BatchInput = normalizeBatchPortScanInput(schedulerInput.BatchInput)
	defer signalSchedulerWakeup(ctx, schedulerInput, "dns_preflight_done")
	item := input.Item
	workflowID := input.WorkflowID
	if workflowID == "" {
		workflowID = workflow.GetInfo(ctx).WorkflowExecution.ID
	}
	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultStateActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	itemInput := parseSchedulerWorkItemInput(item)
	sourceTarget := itemInput.SourceTarget
	if sourceTarget == "" {
		sourceTarget = item.Target
	}
	target := item.Target

	if !workflowTargetIsIP(target) {
		dnsxCtx := artifactActivityContext(ctx, "dnsx", schedulerInput.BatchInput.ActivityTimeoutSeconds)
		var dnsxResult artifact.ActivityResult
		err := executeArtifactActivity(dnsxCtx, "dnsx", artifact.Input{
			Target:                target,
			CampaignID:            schedulerInput.BatchInput.CampaignID,
			WorkItemID:            item.ID,
			WorkflowID:            workflowID,
			HeartbeatLeaseSeconds: schedulerRunningLeaseSeconds,
			Data: mustMarshal(map[string]interface{}{
				"target":       target,
				"record_types": []string{"a", "aaaa", "cname", "ns", "mx", "txt"},
			}),
		}, &dnsxResult)
		if err != nil {
			return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
		}
	}

	cdnCtx := artifactActivityContext(ctx, "cdncheck", schedulerInput.BatchInput.ActivityTimeoutSeconds)
	var cdnResult artifact.ActivityResult
	err := executeArtifactActivity(cdnCtx, "cdncheck", artifact.Input{
		Target:                target,
		CampaignID:            schedulerInput.BatchInput.CampaignID,
		WorkItemID:            item.ID,
		WorkflowID:            workflowID,
		HeartbeatLeaseSeconds: schedulerRunningLeaseSeconds,
		Data:                  mustMarshal(map[string]interface{}{"target": target}),
	}, &cdnResult)
	if err != nil {
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
	}

	chunk := batchPortScanChunk{Target: sourceTarget, Chunk: target}
	if err := upsertPortScanBatchChunk(stateCtx, schedulerInput.BatchID, chunk, "", "pending", ""); err != nil {
		return err
	}
	if err := upsertBatchWorkItem(stateCtx, portScanChunkWorkItem(schedulerInput.BatchID, schedulerInput.BatchInput, chunk, "", "pending", "", item.Schedule)); err != nil {
		return err
	}
	return setBatchWorkItemStatus(stateCtx, item.ID, "completed", workflowID, "", false)
}

func ScheduledPlannedDAGWorkItemWorkflow(ctx workflow.Context, input ScheduledWorkItemWorkflowInput) error {
	schedulerInput := input.SchedulerInput
	schedulerInput.BatchInput = normalizeBatchPortScanInput(schedulerInput.BatchInput)
	defer signalSchedulerWakeup(ctx, schedulerInput, "planned_dag_done")
	item := input.Item
	workflowID := input.WorkflowID
	if workflowID == "" {
		workflowID = workflow.GetInfo(ctx).WorkflowExecution.ID
	}
	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultStateActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})

	itemInput := parseSchedulerWorkItemInput(item)
	iteration := itemInput.Iteration
	if iteration <= 0 {
		iteration = 1
	}
	maxIterations := maxPositive(itemInput.MaxIterations, schedulerInput.BatchInput.PlannedDAGMaxIterations)
	item.Input = mustMarshal(schedulerWorkItemInput{
		Target:        item.Target,
		Iteration:     iteration,
		MaxIterations: maxIterations,
	})

	var plan planner.DAGPlan
	if err := workflow.ExecuteActivity(stateCtx, planner.PlanDAGTargetActivityName, planner.PlanDAGRequest{
		Target:     item.Target,
		CampaignID: schedulerInput.BatchInput.CampaignID,
	}).Get(ctx, &plan); err != nil {
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
	}
	items := make([]data.WorkItem, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		for _, actionItem := range actionWorkItemsFromDAGNode(schedulerInput, item, node, iteration, maxIterations) {
			if actionItem.ID == "" {
				continue
			}
			items = append(items, actionItem)
		}
	}
	admitted, err := admitBatchWorkItems(stateCtx, schedulerInput, items)
	if err != nil {
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
	}
	items = admitted
	if err := upsertBatchWorkItems(stateCtx, items); err != nil {
		return err
	}
	return setBatchWorkItemStatus(stateCtx, item.ID, "completed", workflowID, "", false)
}

func ScheduledArtifactWorkItemWorkflow(ctx workflow.Context, input ScheduledWorkItemWorkflowInput) error {
	schedulerInput := input.SchedulerInput
	schedulerInput.BatchInput = normalizeBatchPortScanInput(schedulerInput.BatchInput)
	item := input.Item
	defer signalSchedulerWakeup(ctx, schedulerInput, item.Type+"_done")
	workflowID := input.WorkflowID
	if workflowID == "" {
		workflowID = workflow.GetInfo(ctx).WorkflowExecution.ID
	}
	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultStateActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	if item.Type == "portscan_chunk" {
		return runScheduledPortScanWorkItem(ctx, stateCtx, schedulerInput, item, workflowID)
	}

	itemInput := parseSchedulerWorkItemInput(item)
	actionTarget := itemInput.Target
	if actionTarget == "" {
		actionTarget = item.Target
	}
	if itemInput.RunIf != nil {
		conditionOK, conditionMessage, err := evaluateActionWorkItemCondition(stateCtx, item, itemInput)
		if err != nil {
			return err
		}
		if !conditionOK {
			return deferActionWorkItemCondition(stateCtx, item.ID, workflowID, conditionMessage)
		}
	}
	claimed, err := claimScheduledActionRecord(stateCtx, item, itemInput, workflowID)
	if err != nil {
		return err
	}
	if !claimed {
		reason := "action already running or completed"
		return setBatchWorkItemStatus(stateCtx, item.ID, "skipped", workflowID, reason, false)
	}

	actionCtx := artifactActivityContext(ctx, item.Artifact, schedulerInput.BatchInput.ActivityTimeoutSeconds)
	var actionValue artifact.ActivityResult
	err = executeArtifactActivity(actionCtx, item.Artifact, artifact.Input{
		Target:                actionTarget,
		CampaignID:            schedulerInput.BatchInput.CampaignID,
		WorkItemID:            item.ID,
		WorkflowID:            workflowID,
		HeartbeatLeaseSeconds: schedulerRunningLeaseSeconds,
		Data:                  mustMarshal(itemInput.ActionInput),
	}, &actionValue)
	actionResult := &actionValue
	if err != nil {
		if updateErr := completeScheduledActionRecord(stateCtx, item.ID, false, "", err.Error()); updateErr != nil {
			return updateErr
		}
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, err.Error(), false)
	}
	if actionResult == nil || !actionResult.Success {
		errorMessage := "action failed"
		if actionResult != nil && actionResult.Error != "" {
			errorMessage = actionResult.Error
		}
		if isNoopArtifactAction(item.Artifact, errorMessage, nil) {
			if updateErr := completeScheduledActionRecord(stateCtx, item.ID, false, "skipped", errorMessage); updateErr != nil {
				return updateErr
			}
			return setBatchWorkItemStatus(stateCtx, item.ID, "skipped", workflowID, errorMessage, false)
		}
		if updateErr := completeScheduledActionRecord(stateCtx, item.ID, false, "", errorMessage); updateErr != nil {
			return updateErr
		}
		return setBatchWorkItemStatus(stateCtx, item.ID, schedulerFailureStatus(item), workflowID, errorMessage, false)
	}
	if isNoopArtifactAction(item.Artifact, "", actionResult.Data) {
		reason := "noop action"
		if item.Artifact == "nuclei" {
			reason = "no templates available"
		}
		if updateErr := completeScheduledActionRecord(stateCtx, item.ID, false, "skipped", reason); updateErr != nil {
			return updateErr
		}
		return setBatchWorkItemStatus(stateCtx, item.ID, "skipped", workflowID, reason, false)
	}
	if shouldReplanAfterAction(item.Type) {
		if err := upsertNextPlannedDAGFollowUp(stateCtx, schedulerInput, item); err != nil {
			return err
		}
	}
	if err := completeScheduledActionRecord(stateCtx, item.ID, true, "", ""); err != nil {
		return err
	}
	return setBatchWorkItemStatus(stateCtx, item.ID, "completed", workflowID, "", false)
}

func isNoopArtifactAction(artifactName, errorMessage string, raw []byte) bool {
	if artifactName != "nuclei" {
		return false
	}
	if errorMessage != "" {
		value := strings.ToLower(errorMessage)
		return strings.Contains(value, "no templates available") ||
			strings.Contains(value, "no templates provided") ||
			strings.Contains(value, "no templates found")
	}
	if len(raw) == 0 {
		return false
	}
	var out struct {
		SkippedReason string `json:"skipped_reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false
	}
	return out.SkippedReason == "no_templates_available"
}

func claimScheduledActionRecord(ctx workflow.Context, item data.WorkItem, itemInput schedulerWorkItemInput, workflowID string) (bool, error) {
	action := scheduledPlannerAction(item, itemInput, workflowID)
	action.Status = "running"
	var claimed bool
	err := workflow.ExecuteActivity(ctx, planner.ClaimActionActivityName, action).Get(ctx, &claimed)
	return claimed, err
}

func completeScheduledActionRecord(ctx workflow.Context, actionID string, success bool, status, errorMessage string) error {
	return workflow.ExecuteActivity(ctx, planner.CompleteActionActivityName, planner.ActionCompletion{
		ID:      actionID,
		Success: success,
		Status:  status,
		Error:   errorMessage,
	}).Get(ctx, nil)
}

func deferActionWorkItemCondition(ctx workflow.Context, itemID, workflowID, reason string) error {
	if reason == "" {
		reason = "run_if condition was not satisfied"
	}
	return setBatchWorkItemStatus(ctx, itemID, data.WorkItemStatusRetryWaiting, workflowID, "condition_wait: "+reason, false)
}

func executeArtifactActivity(activityCtx workflow.Context, activityName string, input artifact.Input, result *artifact.ActivityResult) error {
	return workflow.ExecuteActivity(activityCtx, activityName, input).Get(activityCtx, result)
}

func scheduledPlannerAction(item data.WorkItem, itemInput schedulerWorkItemInput, workflowID string) planner.Action {
	input := copyActionInput(itemInput.ActionInput)
	plannerMeta, _ := input["_planner"].(map[string]interface{})
	if plannerMeta == nil {
		plannerMeta = map[string]interface{}{}
		input["_planner"] = plannerMeta
	}
	if itemInput.DedupKey != "" {
		plannerMeta["dedup_key"] = itemInput.DedupKey
	}
	if itemInput.Risk != "" {
		plannerMeta["risk"] = itemInput.Risk
	}
	if itemInput.Cost > 0 {
		plannerMeta["cost"] = itemInput.Cost
	}
	return planner.Action{
		ID:         item.ID,
		CampaignID: item.CampaignID,
		WorkflowID: workflowID,
		Attempts:   item.Attempts,
		Target:     item.Target,
		Artifact:   item.Artifact,
		Input:      input,
		Decision:   planner.Decision{Schedule: data.NormalizeSchedule(item.Schedule)},
		Reason:     itemInput.Reason,
		Status:     item.Status,
		Risk:       itemInput.Risk,
		Cost:       itemInput.Cost,
		DedupKey:   itemInput.DedupKey,
	}
}

func artifactWorkItemChildWorkflowID(batchID, itemType, target, itemID string, attempts int) string {
	return fmt.Sprintf("%s-%s-%s-%s-%d", batchID, itemType, safeWorkflowIDPart(target), itemID, attempts)
}

func evaluateActionWorkItemCondition(ctx workflow.Context, item data.WorkItem, itemInput schedulerWorkItemInput) (bool, string, error) {
	request := *itemInput.RunIf
	if request.Target == "" {
		if itemInput.Target != "" {
			request.Target = itemInput.Target
		} else {
			request.Target = item.Target
		}
	}
	var conditionResult planner.ConditionResult
	if err := workflow.ExecuteActivity(ctx, planner.EvaluateConditionActivityName, request).Get(ctx, &conditionResult); err != nil {
		return false, "", err
	}
	if conditionResult.OK {
		return true, "", nil
	}
	if conditionResult.Message != "" {
		return false, conditionResult.Message, nil
	}
	return false, "run_if condition was not satisfied", nil
}

type portScanPlannerSignal struct {
	HasAssets bool
	Schedule  string
}

func portScanChunkPlannerSignal(ctx workflow.Context, input SchedulerWorkflowInput, target string) (portScanPlannerSignal, error) {
	request := planner.ConditionRequest{
		Target:     target,
		CampaignID: input.BatchInput.CampaignID,
		Any: []planner.AssetCondition{
			{EventType: "new", Source: "gogo", MinCount: 1},
			{EventType: "changed", Source: "gogo", MinCount: 1},
			{EventType: "status_changed", Source: "gogo", MinCount: 1},
			{Type: "service", Source: "gogo", Status: "observed", MinCount: 1},
			{Type: "service", Source: "gogo", Status: "candidate", MinCount: 1},
			{Type: "service", Source: "gogo", Status: "interesting", MinCount: 1},
			{Type: "service", Source: "gogo", Status: "confirmed", MinCount: 1},
			{Type: "fingerprint", Source: "gogo", Status: "observed", MinCount: 1},
			{Type: "fingerprint", Source: "gogo", Status: "candidate", MinCount: 1},
			{Type: "fingerprint", Source: "gogo", Status: "interesting", MinCount: 1},
			{Type: "fingerprint", Source: "gogo", Status: "confirmed", MinCount: 1},
		},
	}
	var result planner.ConditionResult
	if err := workflow.ExecuteActivity(ctx, planner.EvaluateConditionActivityName, request).Get(ctx, &result); err != nil {
		return portScanPlannerSignal{}, err
	}
	if !result.OK {
		return portScanPlannerSignal{}, nil
	}
	signal := portScanPlannerSignal{HasAssets: true}
	for _, count := range result.Counts {
		if !count.OK {
			continue
		}
		if schedule := plannerSignalSchedule(count.Condition); schedulePrecedes(schedule, signal.Schedule) {
			signal.Schedule = schedule
		}
	}
	if signal.Schedule == "" {
		signal.Schedule = data.ScheduleBatch
	}
	return signal, nil
}

func plannerSignalSchedule(condition planner.AssetCondition) string {
	switch condition.EventType {
	case "changed", "status_changed":
		return data.ScheduleNow
	case "new":
		return data.ScheduleNow
	}
	switch condition.Type {
	case "fingerprint":
		switch condition.Status {
		case "interesting", "confirmed":
			return data.ScheduleNow
		case "observed", "candidate":
			return data.ScheduleNow
		}
	case "service":
		switch condition.Status {
		case "interesting", "confirmed":
			return data.ScheduleNow
		case "candidate":
			return data.ScheduleNow
		case "observed":
			return data.ScheduleBatch
		}
	}
	return data.ScheduleBatch
}

func schedulePrecedes(candidate, current string) bool {
	if current == "" {
		return candidate != ""
	}
	return scheduleOrder(candidate) < scheduleOrder(current)
}

func scheduleOrder(schedule string) int {
	switch data.NormalizeSchedule(schedule) {
	case data.ScheduleNow:
		return 0
	default:
		return 1
	}
}

func mergeSchedule(a, b string) string {
	if data.NormalizeSchedule(a) == data.ScheduleNow || data.NormalizeSchedule(b) == data.ScheduleNow {
		return data.ScheduleNow
	}
	return data.ScheduleBatch
}

func claimScheduledWorkItem(ctx workflow.Context, input SchedulerWorkflowInput, itemType, schedule string, maxRunning int) (data.WorkItem, error) {
	var item data.WorkItem
	queue := schedulerQueueForType(itemType)
	artifactName := schedulerArtifactForType(itemType)
	err := workflow.ExecuteActivity(ctx, planner.ClaimWorkItemActivityName, data.WorkItemClaimRequest{
		CampaignID:   input.BatchInput.CampaignID,
		BatchID:      input.BatchID,
		Type:         itemType,
		Artifact:     artifactName,
		Queue:        queue,
		WorkflowID:   workflow.GetInfo(ctx).WorkflowExecution.ID,
		LeaseSeconds: schedulerLeaseSeconds(),
		Schedule:     data.NormalizeSchedule(schedule),
		MaxRunning:   maxRunning,
	}).Get(ctx, &item)
	return item, err
}

func loadSchedulerSummary(ctx workflow.Context, input SchedulerWorkflowInput, result *SchedulerWorkflowResult) error {
	snapshot, err := loadSchedulerSnapshot(ctx, input)
	if err != nil {
		return err
	}
	loadSchedulerSummaryFromSnapshot(snapshot, input, result)
	return nil
}

func loadSchedulerSnapshot(ctx workflow.Context, input SchedulerWorkflowInput) (data.WorkItemProgressSummary, error) {
	var summary data.WorkItemProgressSummary
	err := workflow.ExecuteActivity(ctx, planner.SchedulerSnapshotActivityName, planner.SchedulerSnapshotRequest{
		CampaignID: input.BatchInput.CampaignID,
		BatchID:    input.BatchID,
	}).Get(ctx, &summary)
	if summary.ByStatus == nil {
		summary.ByStatus = map[string]int{}
	}
	return summary, err
}

func updateSchedulerCapacity(ctx workflow.Context, input SchedulerWorkflowInput) (schedulerCapacityMap, error) {
	var capacities []data.SchedulerCapacity
	err := workflow.ExecuteActivity(ctx, planner.UpdateSchedulerCapacityActivityName, data.SchedulerCapacityUpdateRequest{
		CampaignID: input.BatchInput.CampaignID,
		BatchID:    input.BatchID,
	}).Get(ctx, &capacities)
	out := schedulerCapacityMap{}
	for _, capacity := range capacities {
		if capacity.Queue == "" {
			continue
		}
		if capacity.EffectiveCapacity <= 0 {
			continue
		}
		out[capacity.Queue] = capacity.EffectiveCapacity
	}
	if len(out) == 0 {
		for _, policy := range data.DefaultSchedulerCapacityPolicies() {
			out[policy.Queue] = policy.Initial
		}
	}
	return out, err
}

type schedulerWorkItemSummary struct {
	ByStatus map[string]int
	Total    int
}

func schedulerSummaryForType(snapshot data.WorkItemProgressSummary, itemType string) schedulerWorkItemSummary {
	for _, group := range snapshot.ByType {
		if group.Key == itemType {
			return workItemSummaryFromGroup(group)
		}
	}
	return schedulerWorkItemSummary{ByStatus: map[string]int{}, Total: 0}
}

func workItemSummaryFromGroup(group data.WorkItemGroupSummary) schedulerWorkItemSummary {
	return schedulerWorkItemSummary{
		Total: group.Total,
		ByStatus: map[string]int{
			data.WorkItemStatusPending:      group.Pending,
			data.WorkItemStatusRunning:      group.Running,
			data.WorkItemStatusCompleted:    group.Completed,
			data.WorkItemStatusFailed:       group.Failed,
			data.WorkItemStatusRetryWaiting: group.RetryWaiting,
			data.WorkItemStatusPaused:       group.Paused,
			data.WorkItemStatusCancelled:    group.Cancelled,
			data.WorkItemStatusSkipped:      group.Skipped,
			data.WorkItemStatusDead:         group.Dead,
		},
	}
}

func loadSchedulerSummaryFromSnapshot(snapshot data.WorkItemProgressSummary, input SchedulerWorkflowInput, result *SchedulerWorkflowResult) {
	preflight := schedulerSummaryForType(snapshot, "dns_preflight")
	result.PreflightTotal = preflight.Total
	result.PreflightDone = preflight.ByStatus["completed"]
	result.PreflightFailed = preflight.ByStatus["failed"] + preflight.ByStatus["dead"]
	result.PreflightPending = preflight.ByStatus["pending"] + preflight.ByStatus["retry_waiting"] + preflight.ByStatus["paused"]
	result.PreflightRunning = preflight.ByStatus["running"]
	portscan := schedulerSummaryForType(snapshot, "portscan_chunk")
	result.PortScanTotal = portscan.Total
	result.PortScanDone = portscan.ByStatus["completed"]
	result.PortScanFailed = portscan.ByStatus["failed"] + portscan.ByStatus["dead"]
	result.PortScanPending = portscan.ByStatus["pending"] + portscan.ByStatus["retry_waiting"] + portscan.ByStatus["paused"]
	result.PortScanRunning = portscan.ByStatus["running"]
	if input.BatchInput.RunPlannedDAG {
		followUp := schedulerSummaryForType(snapshot, "planned_dag_followup")
		result.FollowUpTotal = followUp.Total
		result.FollowUpDone = followUp.ByStatus["completed"]
		result.FollowUpFailed = followUp.ByStatus["failed"] + followUp.ByStatus["dead"]
		result.FollowUpPending = followUp.ByStatus["pending"] + followUp.ByStatus["retry_waiting"] + followUp.ByStatus["paused"]
		result.FollowUpRunning = followUp.ByStatus["running"]
		for _, itemType := range scheduledActionItemTypes() {
			phaseSummary := schedulerSummaryForType(snapshot, itemType)
			result.ActionTotal += phaseSummary.Total
			result.ActionDone += phaseSummary.ByStatus["completed"] + phaseSummary.ByStatus["skipped"]
			result.ActionFailed += phaseSummary.ByStatus["failed"] + phaseSummary.ByStatus["dead"]
			result.ActionPending += phaseSummary.ByStatus["pending"] + phaseSummary.ByStatus["retry_waiting"] + phaseSummary.ByStatus["paused"]
			result.ActionRunning += phaseSummary.ByStatus["running"]
		}
	}
}

func schedulerLeaseSeconds() int {
	return schedulerRunningLeaseSeconds
}

func schedulerQueueForType(itemType string) string {
	if def, ok := data.WorkItemDefinitionForType(itemType); ok {
		return def.Queue
	}
	return itemType
}

func schedulerArtifactForType(itemType string) string {
	if def, ok := data.WorkItemDefinitionForType(itemType); ok {
		return def.Artifact
	}
	return itemType
}

func recoverScheduledWorkItems(ctx workflow.Context, input SchedulerWorkflowInput) error {
	var result recovery.RecoveryResult
	return workflow.ExecuteActivity(ctx, planner.RecoverWorkItemsActivityName, recovery.RecoveryPolicy{
		Filter: data.WorkItemFilter{
			CampaignID: input.BatchInput.CampaignID,
			BatchID:    input.BatchID,
		},
		Limit:                1000,
		RecoverFailures:      true,
		RecoverExpiredLeases: true,
	}).Get(ctx, &result)
}

func scheduledBatchStatus(result *SchedulerWorkflowResult) string {
	if result.PreflightPending > 0 || result.PreflightRunning > 0 || result.PortScanPending > 0 || result.PortScanRunning > 0 || result.FollowUpPending > 0 || result.FollowUpRunning > 0 || result.ActionPending > 0 || result.ActionRunning > 0 {
		return "running"
	}
	if result.PreflightFailed > 0 && result.PortScanDone == 0 && result.PortScanPending == 0 && result.PortScanRunning == 0 {
		return "failed"
	}
	if result.PortScanFailed > 0 && result.PortScanDone > 0 {
		return "partial"
	}
	if result.PortScanFailed > 0 && result.PortScanDone == 0 {
		return "failed"
	}
	if result.PreflightFailed > 0 || result.FollowUpFailed > 0 || result.ActionFailed > 0 {
		return "partial"
	}
	return "completed"
}

func finalizeScheduledBatch(ctx workflow.Context, input SchedulerWorkflowInput, result *SchedulerWorkflowResult) error {
	batchResult := &BatchPortScanResult{
		Targets:        input.BatchInput.Targets,
		Ports:          input.BatchInput.Ports,
		ChunkPrefix:    input.BatchInput.ChunkPrefix,
		MaxAttempts:    input.BatchInput.MaxAttempts,
		RetryDelay:     input.BatchInput.RetryDelaySeconds,
		CampaignPhase:  input.BatchInput.CampaignPhase,
		RunPlannedDAG:  input.BatchInput.RunPlannedDAG,
		TotalChunks:    input.TotalChunks,
		Completed:      result.PortScanDone,
		Failed:         result.PortScanFailed,
		FollowUpTotal:  result.FollowUpTotal,
		FollowUpFailed: result.FollowUpFailed,
		ActionTotal:    result.ActionTotal,
		ActionFailed:   result.ActionFailed,
	}
	status := result.Status
	if status == "" {
		status = scheduledBatchStatus(result)
	}
	return upsertPortScanBatchRun(ctx, input.BatchID, input.BatchInput, batchResult, status)
}

func shouldContinueScheduler(input SchedulerWorkflowInput, processed int) bool {
	return processed >= input.ContinueAfter && input.ContinuedRuns < input.MaxContinueRuns
}

func nextSchedulerInput(input SchedulerWorkflowInput) SchedulerWorkflowInput {
	input.ContinuedRuns++
	return input
}

func schedulerFailureStatus(item data.WorkItem) string {
	if item.MaxAttempts > 0 && item.Attempts < item.MaxAttempts {
		return "retry_waiting"
	}
	return "failed"
}

func parseSchedulerWorkItemInput(item data.WorkItem) schedulerWorkItemInput {
	var out schedulerWorkItemInput
	_ = json.Unmarshal(item.Input, &out)
	return out
}

func plannedDAGFollowUpWorkItemFromScheduler(input SchedulerWorkflowInput, parent data.WorkItem, schedule string) data.WorkItem {
	if schedule == "" {
		schedule = parent.Schedule
	}
	return plannedDAGFollowUpWorkItem(input, parent.Target, parent.ID, 1, input.BatchInput.PlannedDAGMaxIterations, schedule)
}

func shouldReplanAfterAction(itemType string) bool {
	switch itemType {
	case "fingers_action", "spray_shard":
		return true
	default:
		return false
	}
}

func upsertNextPlannedDAGFollowUp(ctx workflow.Context, input SchedulerWorkflowInput, item data.WorkItem) error {
	itemInput := parseSchedulerWorkItemInput(item)
	iteration := itemInput.Iteration
	if iteration <= 0 {
		iteration = 1
	}
	maxIterations := itemInput.MaxIterations
	if maxIterations <= 0 {
		maxIterations = input.BatchInput.PlannedDAGMaxIterations
	}
	if maxIterations <= 0 || iteration >= maxIterations {
		return nil
	}
	return upsertBatchWorkItem(ctx, plannedDAGFollowUpWorkItem(input, item.Target, item.ID, iteration+1, maxIterations, item.Schedule))
}

func admitBatchWorkItems(ctx workflow.Context, input SchedulerWorkflowInput, items []data.WorkItem) ([]data.WorkItem, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var result admission.Result
	err := workflow.ExecuteActivity(ctx, planner.AdmitWorkItemsActivityName, planner.AdmitWorkItemsRequest{
		CampaignID:   input.BatchInput.CampaignID,
		BatchID:      input.BatchID,
		ScopeTargets: input.BatchInput.Targets,
		Items:        items,
	}).Get(ctx, &result)
	if err != nil {
		return nil, err
	}
	return result.Admitted, nil
}

func plannedDAGFollowUpWorkItem(input SchedulerWorkflowInput, target, parentID string, iteration, maxIterations int, schedule string) data.WorkItem {
	if iteration <= 0 {
		iteration = 1
	}
	if maxIterations <= 0 {
		maxIterations = input.BatchInput.PlannedDAGMaxIterations
	}
	return data.WorkItem{
		ID:          plannedDAGFollowUpWorkItemID(input.BatchID, target, iteration),
		CampaignID:  input.BatchInput.CampaignID,
		BatchID:     input.BatchID,
		ParentID:    parentID,
		Type:        "planned_dag_followup",
		Target:      target,
		Artifact:    "planned_dag",
		Queue:       "planner",
		Input:       mustMarshal(map[string]interface{}{"target": target, "iteration": iteration, "max_iterations": maxIterations}),
		Schedule:    data.NormalizeSchedule(schedule),
		Status:      "pending",
		MaxAttempts: 1,
	}
}

func maxPositive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func copyActionInput(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringFromActionInput(input map[string]interface{}, key string) string {
	if input == nil {
		return ""
	}
	value, _ := input[key].(string)
	return value
}

func normalizeBatchPortScanInput(input BatchPortScanInput) BatchPortScanInput {
	input.Ports = strings.TrimSpace(input.Ports)
	if input.ChunkPrefix <= 0 || input.ChunkPrefix > 32 {
		input.ChunkPrefix = defaultCIDRChunkPrefix
	}
	if input.MaxAttempts <= 0 {
		input.MaxAttempts = 1
	}
	if input.MaxAttempts > 5 {
		input.MaxAttempts = 5
	}
	if input.RetryDelaySeconds <= 0 {
		input.RetryDelaySeconds = 30
	}
	if input.RetryDelaySeconds > 3600 {
		input.RetryDelaySeconds = 3600
	}
	input.CampaignPhase = NormalizeCampaignPhase(input.CampaignPhase)
	if input.PlannedDAGMaxIterations <= 0 {
		input.PlannedDAGMaxIterations = 5
	}
	if input.PlannedDAGMaxIterations > 20 {
		input.PlannedDAGMaxIterations = 20
	}
	return input
}
