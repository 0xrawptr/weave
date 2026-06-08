package workflow

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type SchedulerWorkflowInput struct {
	BatchID         string             `json:"batch_id"`
	BatchInput      BatchPortScanInput `json:"batch_input"`
	TotalChunks     int                `json:"total_chunks"`
	ContinueAfter   int                `json:"continue_after,omitempty"`
	IdleWaitSeconds int                `json:"idle_wait_seconds,omitempty"`
	ContinuedRuns   int                `json:"continued_runs,omitempty"`
	MaxContinueRuns int                `json:"max_continue_runs,omitempty"`
}

type SchedulerWorkflowResult struct {
	BatchID          string `json:"batch_id"`
	Status           string `json:"status"`
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

type schedulerChild struct {
	Item       data.WorkItem
	WorkflowID string
	Future     workflow.Future
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

func SchedulerWorkflow(ctx workflow.Context, input SchedulerWorkflowInput) (*SchedulerWorkflowResult, error) {
	input.BatchInput = normalizeBatchPortScanInput(input.BatchInput)
	if input.BatchID == "" {
		input.BatchID = workflow.GetInfo(ctx).WorkflowExecution.ID
	}
	if input.ContinueAfter <= 0 {
		input.ContinueAfter = 50
	}
	if input.IdleWaitSeconds <= 0 {
		input.IdleWaitSeconds = 30
	}
	if input.MaxContinueRuns <= 0 {
		input.MaxContinueRuns = 10000
	}

	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: defaultStateActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	result := &SchedulerWorkflowResult{BatchID: input.BatchID, ContinuedRuns: input.ContinuedRuns}
	if err := recoverStaleScheduledWorkItems(stateCtx, input); err != nil {
		return result, err
	}
	if err := requeueRetryWaitingScheduledWorkItems(stateCtx, input); err != nil {
		return result, err
	}

	processed, paused, err := schedulePortScanChunks(ctx, stateCtx, input)
	result.ProcessedThisRun += processed
	if err != nil || paused {
		result.Status = "paused"
		if err != nil {
			return result, err
		}
		if summaryErr := loadSchedulerSummary(stateCtx, input, result); summaryErr != nil {
			return result, summaryErr
		}
		if updateErr := finalizeScheduledBatch(stateCtx, input, result); updateErr != nil {
			return result, updateErr
		}
		return result, nil
	}
	if shouldContinueScheduler(input, result.ProcessedThisRun) {
		return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
	}

	if input.BatchInput.RunPlannedDAG {
		processed, paused, err = schedulePlannedDAGFollowUps(ctx, stateCtx, input)
		result.ProcessedThisRun += processed
		if err != nil || paused {
			result.Status = "paused"
			if err != nil {
				return result, err
			}
			if summaryErr := loadSchedulerSummary(stateCtx, input, result); summaryErr != nil {
				return result, summaryErr
			}
			if updateErr := finalizeScheduledBatch(stateCtx, input, result); updateErr != nil {
				return result, updateErr
			}
			return result, nil
		}
		if shouldContinueScheduler(input, result.ProcessedThisRun) {
			return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
		}

		for _, phase := range scheduledActionPhases() {
			processed, paused, err = scheduleArtifactActions(ctx, stateCtx, input, phase.itemType, phase.maxConcurrency(input))
			result.ProcessedThisRun += processed
			if err != nil || paused {
				result.Status = "paused"
				if err != nil {
					return result, err
				}
				if summaryErr := loadSchedulerSummary(stateCtx, input, result); summaryErr != nil {
					return result, summaryErr
				}
				if updateErr := finalizeScheduledBatch(stateCtx, input, result); updateErr != nil {
					return result, updateErr
				}
				return result, nil
			}
			if shouldContinueScheduler(input, result.ProcessedThisRun) {
				return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
			}
		}
	}

	if err := loadSchedulerSummary(stateCtx, input, result); err != nil {
		return result, err
	}
	result.Status = scheduledBatchStatus(result)
	if result.Status == "running" && input.ContinuedRuns < input.MaxContinueRuns {
		if err := workflow.Sleep(ctx, time.Duration(input.IdleWaitSeconds)*time.Second); err != nil {
			return result, err
		}
		return result, workflow.NewContinueAsNewError(ctx, SchedulerWorkflow, nextSchedulerInput(input))
	}
	if err := finalizeScheduledBatch(stateCtx, input, result); err != nil {
		return result, err
	}
	return result, nil
}

func schedulePortScanChunks(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput) (int, bool, error) {
	return scheduleWorkItemPhase(ctx, stateCtx, input, "portscan_chunk", input.BatchInput.MaxConcurrency, func(item data.WorkItem) (schedulerChild, error) {
		itemInput := parseSchedulerWorkItemInput(item)
		sourceTarget := itemInput.SourceTarget
		if sourceTarget == "" {
			sourceTarget = item.Target
		}
		childID := fmt.Sprintf("%s-portscan-%s-%d", input.BatchID, safeWorkflowIDPart(item.Target), item.Attempts)
		if err := upsertPortScanBatchChunk(stateCtx, input.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: item.Target}, childID, "running", ""); err != nil {
			return schedulerChild{}, err
		}
		if err := setBatchWorkItemStatus(stateCtx, item.ID, "running", childID, "", false); err != nil {
			return schedulerChild{}, err
		}
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID: childID,
		})
		future := workflow.ExecuteChildWorkflow(childCtx, PortScanWorkflow, PortScanInput{
			IP:                     item.Target,
			CampaignID:             input.BatchInput.CampaignID,
			Ports:                  input.BatchInput.Ports,
			ActivityTimeoutSeconds: input.BatchInput.ActivityTimeoutSeconds,
		})
		return schedulerChild{Item: item, WorkflowID: childID, Future: future}, nil
	}, func(child schedulerChild) error {
		var portscanResult PortScanResult
		childErr := child.Future.Get(ctx, &portscanResult)
		itemInput := parseSchedulerWorkItemInput(child.Item)
		sourceTarget := itemInput.SourceTarget
		if sourceTarget == "" {
			sourceTarget = child.Item.Target
		}
		if childErr != nil {
			if err := upsertPortScanBatchChunk(stateCtx, input.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: child.Item.Target}, child.WorkflowID, "failed", childErr.Error()); err != nil {
				return err
			}
			return setBatchWorkItemStatus(stateCtx, child.Item.ID, schedulerFailureStatus(child.Item), child.WorkflowID, childErr.Error(), false)
		}
		if err := upsertPortScanBatchChunk(stateCtx, input.BatchID, batchPortScanChunk{Target: sourceTarget, Chunk: child.Item.Target}, child.WorkflowID, "completed", ""); err != nil {
			return err
		}
		if err := setBatchWorkItemStatus(stateCtx, child.Item.ID, "completed", child.WorkflowID, "", false); err != nil {
			return err
		}
		if input.BatchInput.RunPlannedDAG {
			return upsertBatchWorkItem(stateCtx, plannedDAGFollowUpWorkItemFromScheduler(input, child.Item))
		}
		return nil
	})
}

func schedulePlannedDAGFollowUps(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput) (int, bool, error) {
	return scheduleWorkItemPhase(ctx, stateCtx, input, "planned_dag_followup", input.BatchInput.PlannedDAGConcurrency, func(item data.WorkItem) (schedulerChild, error) {
		itemInput := parseSchedulerWorkItemInput(item)
		iteration := itemInput.Iteration
		if iteration <= 0 {
			iteration = 1
		}
		childID := fmt.Sprintf("%s-planned-dag-%s-%d", input.BatchID, safeWorkflowIDPart(item.Target), item.Attempts)
		if err := setBatchWorkItemStatus(stateCtx, item.ID, "running", childID, "", false); err != nil {
			return schedulerChild{}, err
		}
		future := workflow.ExecuteActivity(stateCtx, planner.PlanDAGTargetActivityName, planner.PlanDAGRequest{
			Target:     item.Target,
			CampaignID: input.BatchInput.CampaignID,
		})
		item.Input = mustMarshal(schedulerWorkItemInput{
			Target:        item.Target,
			Iteration:     iteration,
			MaxIterations: maxPositive(itemInput.MaxIterations, input.BatchInput.PlannedDAGMaxIterations),
		})
		return schedulerChild{Item: item, WorkflowID: childID, Future: future}, nil
	}, func(child schedulerChild) error {
		finalStatus := "completed"
		finalError := ""
		var plan planner.DAGPlan
		if childErr := child.Future.Get(ctx, &plan); childErr == nil {
			itemInput := parseSchedulerWorkItemInput(child.Item)
			items := make([]data.WorkItem, 0, len(plan.Nodes))
			for _, node := range plan.Nodes {
				for _, item := range actionWorkItemsFromDAGNode(input, child.Item, node, itemInput.Iteration, itemInput.MaxIterations) {
					if item.ID == "" {
						continue
					}
					items = append(items, item)
				}
			}
			if err := upsertBatchWorkItems(stateCtx, items); err != nil {
				return err
			}
		} else {
			finalStatus = "failed"
			finalError = childErr.Error()
		}
		return setBatchWorkItemStatus(stateCtx, child.Item.ID, finalStatus, child.WorkflowID, finalError, false)
	})
}

type schedulerActionPhase struct {
	itemType       string
	maxConcurrency func(SchedulerWorkflowInput) int
}

func scheduledActionPhases() []schedulerActionPhase {
	return []schedulerActionPhase{
		{itemType: "fingers_action", maxConcurrency: func(input SchedulerWorkflowInput) int { return input.BatchInput.PlannedDAGConcurrency }},
		{itemType: "spray_shard", maxConcurrency: func(input SchedulerWorkflowInput) int { return schedulerQueueLimit(input, "spray") }},
		{itemType: "nuclei_group", maxConcurrency: func(input SchedulerWorkflowInput) int { return schedulerQueueLimit(input, "nuclei") }},
	}
}

func scheduleArtifactActions(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, itemType string, maxConcurrency int) (int, bool, error) {
	return scheduleWorkItemPhase(ctx, stateCtx, input, itemType, maxConcurrency, func(item data.WorkItem) (schedulerChild, error) {
		itemInput := parseSchedulerWorkItemInput(item)
		actionTarget := itemInput.Target
		if actionTarget == "" {
			actionTarget = item.Target
		}
		if itemInput.RunIf != nil {
			conditionOK, conditionMessage, err := evaluateActionWorkItemCondition(stateCtx, item, itemInput)
			if err != nil {
				return schedulerChild{}, err
			}
			if !conditionOK {
				if err := skipScheduledActionRecord(stateCtx, item, itemInput, conditionMessage); err != nil {
					return schedulerChild{}, err
				}
				if err := setBatchWorkItemStatus(stateCtx, item.ID, "skipped", "", conditionMessage, false); err != nil {
					return schedulerChild{}, err
				}
				return schedulerChild{Item: item, WorkflowID: "", Future: nil}, nil
			}
		}
		childID := actionChildWorkflowID(input.BatchID, itemType, actionTarget, item.ID, item.Attempts)
		claimed, err := claimScheduledActionRecord(stateCtx, item, itemInput, childID)
		if err != nil {
			return schedulerChild{}, err
		}
		if !claimed {
			reason := "action already running or completed"
			if err := setBatchWorkItemStatus(stateCtx, item.ID, "skipped", childID, reason, false); err != nil {
				return schedulerChild{}, err
			}
			return schedulerChild{Item: item, WorkflowID: "", Future: nil}, nil
		}
		if err := setBatchWorkItemStatus(stateCtx, item.ID, "running", childID, "", false); err != nil {
			return schedulerChild{}, err
		}
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{WorkflowID: childID})
		future := workflow.ExecuteChildWorkflow(childCtx, ActionWorkflow, ActionWorkflowInput{
			Artifact:               item.Artifact,
			Target:                 actionTarget,
			CampaignID:             input.BatchInput.CampaignID,
			Input:                  itemInput.ActionInput,
			ActivityTimeoutSeconds: input.BatchInput.ActivityTimeoutSeconds,
		})
		return schedulerChild{Item: item, WorkflowID: childID, Future: future}, nil
	}, func(child schedulerChild) error {
		if child.Future == nil {
			return nil
		}
		var actionResult artifact.ActivityResult
		childErr := child.Future.Get(ctx, &actionResult)
		if childErr != nil {
			if err := completeScheduledActionRecord(stateCtx, child.Item.ID, false, "", childErr.Error()); err != nil {
				return err
			}
			return setBatchWorkItemStatus(stateCtx, child.Item.ID, schedulerFailureStatus(child.Item), child.WorkflowID, childErr.Error(), false)
		}
		if !actionResult.Success {
			if err := completeScheduledActionRecord(stateCtx, child.Item.ID, false, "", actionResult.Error); err != nil {
				return err
			}
			return setBatchWorkItemStatus(stateCtx, child.Item.ID, schedulerFailureStatus(child.Item), child.WorkflowID, actionResult.Error, false)
		}
		if shouldReplanAfterAction(child.Item.Type) {
			if err := upsertNextPlannedDAGFollowUp(stateCtx, input, child.Item); err != nil {
				return err
			}
		}
		if err := completeScheduledActionRecord(stateCtx, child.Item.ID, true, "", ""); err != nil {
			return err
		}
		return setBatchWorkItemStatus(stateCtx, child.Item.ID, "completed", child.WorkflowID, "", false)
	})
}

func claimScheduledActionRecord(ctx workflow.Context, item data.WorkItem, itemInput schedulerWorkItemInput, workflowID string) (bool, error) {
	action := scheduledPlannerAction(item, itemInput, workflowID)
	action.Status = "running"
	var claimed bool
	err := workflow.ExecuteActivity(ctx, planner.ClaimActionActivityName, action).Get(ctx, &claimed)
	return claimed, err
}

func skipScheduledActionRecord(ctx workflow.Context, item data.WorkItem, itemInput schedulerWorkItemInput, reason string) error {
	claimed, err := claimScheduledActionRecord(ctx, item, itemInput, "")
	if err != nil || !claimed {
		return err
	}
	return completeScheduledActionRecord(ctx, item.ID, false, "skipped", reason)
}

func completeScheduledActionRecord(ctx workflow.Context, actionID string, success bool, status, errorMessage string) error {
	return workflow.ExecuteActivity(ctx, planner.CompleteActionActivityName, planner.ActionCompletion{
		ID:      actionID,
		Success: success,
		Status:  status,
		Error:   errorMessage,
	}).Get(ctx, nil)
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
		Target:     item.Target,
		Artifact:   item.Artifact,
		Input:      input,
		Priority:   item.Priority,
		Reason:     itemInput.Reason,
		Status:     item.Status,
		Risk:       itemInput.Risk,
		Cost:       itemInput.Cost,
		DedupKey:   itemInput.DedupKey,
	}
}

func actionChildWorkflowID(batchID, itemType, target, itemID string, attempts int) string {
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

func scheduleWorkItemPhase(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, itemType string, maxConcurrency int, start func(data.WorkItem) (schedulerChild, error), finish func(schedulerChild) error) (int, bool, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	processed := 0
	for processed < input.ContinueAfter {
		if paused, err := campaignPaused(stateCtx, input.BatchInput.CampaignID); err != nil {
			return processed, false, err
		} else if paused {
			return processed, true, nil
		}

		running := make([]schedulerChild, 0, maxConcurrency)
		for len(running) < maxConcurrency && processed < input.ContinueAfter {
			item, err := claimScheduledWorkItem(stateCtx, input, itemType)
			if err != nil {
				return processed, false, err
			}
			if item.ID == "" {
				break
			}
			child, err := start(item)
			if err != nil {
				return processed, false, err
			}
			if child.Future == nil {
				processed++
				continue
			}
			running = append(running, child)
		}
		if len(running) == 0 {
			return processed, false, nil
		}

		batchProcessed, err := waitScheduledChildren(ctx, stateCtx, input, running, finish)
		processed += batchProcessed
		if err != nil {
			return processed, false, err
		}
	}
	return processed, false, nil
}

func waitScheduledChildren(ctx, stateCtx workflow.Context, input SchedulerWorkflowInput, running []schedulerChild, finish func(schedulerChild) error) (int, error) {
	if len(running) == 0 {
		return 0, nil
	}
	selector := workflow.NewSelector(ctx)
	pending := make(map[string]schedulerChild, len(running))
	remaining := len(running)
	processed := 0
	var firstErr error

	for _, item := range running {
		child := item
		pending[child.Item.ID] = child
		selector.AddFuture(child.Future, func(workflow.Future) {
			delete(pending, child.Item.ID)
			if err := finish(child); err != nil && firstErr == nil {
				firstErr = err
			}
			processed++
			remaining--
		})
	}

	renewDue := false
	addRenewTimer := func() {
		selector.AddFuture(workflow.NewTimer(ctx, schedulerRenewInterval(input)), func(workflow.Future) {
			renewDue = true
		})
	}
	addRenewTimer()

	for remaining > 0 {
		selector.Select(ctx)
		if renewDue {
			renewDue = false
			for _, child := range pending {
				if err := renewScheduledWorkItem(stateCtx, input, child); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			if remaining > 0 {
				addRenewTimer()
			}
		}
	}
	return processed, firstErr
}

func claimScheduledWorkItem(ctx workflow.Context, input SchedulerWorkflowInput, itemType string) (data.WorkItem, error) {
	var item data.WorkItem
	queue := schedulerQueueForType(itemType)
	artifactName := schedulerArtifactForType(itemType)
	err := workflow.ExecuteActivity(ctx, planner.ClaimWorkItemActivityName, data.WorkItemClaimRequest{
		CampaignID:            input.BatchInput.CampaignID,
		BatchID:               input.BatchID,
		Type:                  itemType,
		Artifact:              artifactName,
		Queue:                 queue,
		WorkflowID:            workflow.GetInfo(ctx).WorkflowExecution.ID,
		LeaseSeconds:          schedulerLeaseSeconds(input),
		MaxRunning:            schedulerQueueLimit(input, queue),
		MaxRunningPerArtifact: schedulerArtifactLimit(input, artifactName),
		MaxRunningPerCampaign: input.BatchInput.ResourceLimits.MaxRunningCampaign,
		MaxRunningPerTarget:   input.BatchInput.ResourceLimits.MaxRunningTarget,
	}).Get(ctx, &item)
	return item, err
}

func renewScheduledWorkItem(ctx workflow.Context, input SchedulerWorkflowInput, child schedulerChild) error {
	return workflow.ExecuteActivity(ctx, planner.HeartbeatWorkItemActivityName, data.WorkItemHeartbeatRequest{
		ID:           child.Item.ID,
		WorkflowID:   child.WorkflowID,
		LeaseSeconds: schedulerLeaseSeconds(input),
	}).Get(ctx, nil)
}

func loadSchedulerSummary(ctx workflow.Context, input SchedulerWorkflowInput, result *SchedulerWorkflowResult) error {
	portscan, err := workItemSummary(ctx, input, "portscan_chunk")
	if err != nil {
		return err
	}
	result.PortScanTotal = portscan.Total
	result.PortScanDone = portscan.ByStatus["completed"]
	result.PortScanFailed = portscan.ByStatus["failed"] + portscan.ByStatus["dead"]
	result.PortScanPending = portscan.ByStatus["pending"] + portscan.ByStatus["retry_waiting"] + portscan.ByStatus["paused"]
	result.PortScanRunning = portscan.ByStatus["running"]
	if input.BatchInput.RunPlannedDAG {
		followUp, err := workItemSummary(ctx, input, "planned_dag_followup")
		if err != nil {
			return err
		}
		result.FollowUpTotal = followUp.Total
		result.FollowUpDone = followUp.ByStatus["completed"]
		result.FollowUpFailed = followUp.ByStatus["failed"] + followUp.ByStatus["dead"]
		result.FollowUpPending = followUp.ByStatus["pending"] + followUp.ByStatus["retry_waiting"] + followUp.ByStatus["paused"]
		result.FollowUpRunning = followUp.ByStatus["running"]
		for _, phase := range scheduledActionPhases() {
			phaseSummary, err := workItemSummary(ctx, input, phase.itemType)
			if err != nil {
				return err
			}
			result.ActionTotal += phaseSummary.Total
			result.ActionDone += phaseSummary.ByStatus["completed"] + phaseSummary.ByStatus["skipped"]
			result.ActionFailed += phaseSummary.ByStatus["failed"] + phaseSummary.ByStatus["dead"]
			result.ActionPending += phaseSummary.ByStatus["pending"] + phaseSummary.ByStatus["retry_waiting"] + phaseSummary.ByStatus["paused"]
			result.ActionRunning += phaseSummary.ByStatus["running"]
		}
	}
	return nil
}

func schedulerLeaseSeconds(input SchedulerWorkflowInput) int {
	timeout := longActivityTimeout(input.BatchInput.ActivityTimeoutSeconds)
	return int((timeout + timeout/10).Seconds())
}

func schedulerRenewInterval(input SchedulerWorkflowInput) time.Duration {
	seconds := schedulerLeaseSeconds(input) / 3
	if seconds <= 0 || seconds > 60 {
		seconds = 60
	}
	if seconds < 10 {
		seconds = 10
	}
	return time.Duration(seconds) * time.Second
}

func schedulerQueueForType(itemType string) string {
	switch itemType {
	case "portscan_chunk":
		return "portscan"
	case "planned_dag_followup":
		return "planner"
	case "fingers_action":
		return "http"
	case "spray_shard":
		return "spray"
	case "nuclei_group":
		return "nuclei"
	default:
		return itemType
	}
}

func schedulerArtifactForType(itemType string) string {
	switch itemType {
	case "portscan_chunk":
		return "gogo"
	case "planned_dag_followup":
		return "planned_dag"
	case "fingers_action":
		return "fingers"
	case "spray_shard":
		return "spray"
	case "nuclei_group":
		return "nuclei"
	default:
		return itemType
	}
}

func schedulerQueueLimit(input SchedulerWorkflowInput, queue string) int {
	if input.BatchInput.ResourceLimits.Queue != nil {
		if limit := input.BatchInput.ResourceLimits.Queue[queue]; limit > 0 {
			return limit
		}
	}
	if input.BatchInput.QueueLimits != nil {
		if limit := input.BatchInput.QueueLimits[queue]; limit > 0 {
			return limit
		}
	}
	switch queue {
	case "portscan":
		return input.BatchInput.MaxConcurrency
	case "planner":
		return input.BatchInput.PlannedDAGConcurrency
	case "http":
		return input.BatchInput.PlannedDAGConcurrency
	case "spray":
		return minPositive(input.BatchInput.PlannedDAGConcurrency, 3)
	case "nuclei":
		return minPositive(input.BatchInput.PlannedDAGConcurrency, 5)
	default:
		return 1
	}
}

func schedulerArtifactLimit(input SchedulerWorkflowInput, artifactName string) int {
	if input.BatchInput.ResourceLimits.Artifact != nil {
		if limit := input.BatchInput.ResourceLimits.Artifact[artifactName]; limit > 0 {
			return limit
		}
	}
	switch artifactName {
	case "gogo":
		return input.BatchInput.MaxConcurrency
	case "planned_dag":
		return input.BatchInput.PlannedDAGConcurrency
	case "fingers":
		return input.BatchInput.PlannedDAGConcurrency
	case "spray":
		return minPositive(input.BatchInput.PlannedDAGConcurrency, 3)
	case "nuclei":
		return minPositive(input.BatchInput.PlannedDAGConcurrency, 5)
	default:
		return 1
	}
}

func workItemSummary(ctx workflow.Context, input SchedulerWorkflowInput, itemType string) (planner.WorkItemSummary, error) {
	var summary planner.WorkItemSummary
	err := workflow.ExecuteActivity(ctx, planner.WorkItemSummaryActivityName, planner.WorkItemSummaryRequest{
		CampaignID: input.BatchInput.CampaignID,
		BatchID:    input.BatchID,
		Type:       itemType,
	}).Get(ctx, &summary)
	return summary, err
}

func recoverStaleScheduledWorkItems(ctx workflow.Context, input SchedulerWorkflowInput) error {
	var result data.WorkItemBulkResult
	return workflow.ExecuteActivity(ctx, planner.RecoverStaleWorkItemsActivityName, planner.RecoverStaleWorkItemsRequest{
		Filter: data.WorkItemFilter{
			CampaignID: input.BatchInput.CampaignID,
			BatchID:    input.BatchID,
		},
		Limit: 1000,
	}).Get(ctx, &result)
}

func requeueRetryWaitingScheduledWorkItems(ctx workflow.Context, input SchedulerWorkflowInput) error {
	var result data.WorkItemBulkResult
	return workflow.ExecuteActivity(ctx, planner.RequeueRetryWaitingWorkItemsActivityName, planner.RequeueRetryWaitingWorkItemsRequest{
		Filter: data.WorkItemFilter{
			CampaignID: input.BatchInput.CampaignID,
			BatchID:    input.BatchID,
		},
		MinAgeSeconds: input.BatchInput.RetryDelaySeconds,
		Limit:         1000,
	}).Get(ctx, &result)
}

func scheduledBatchStatus(result *SchedulerWorkflowResult) string {
	if result.PortScanPending > 0 || result.PortScanRunning > 0 || result.FollowUpPending > 0 || result.FollowUpRunning > 0 || result.ActionPending > 0 || result.ActionRunning > 0 {
		return "running"
	}
	if result.PortScanFailed > 0 && result.PortScanDone > 0 {
		return "partial"
	}
	if result.PortScanFailed > 0 && result.PortScanDone == 0 {
		return "failed"
	}
	if result.FollowUpFailed > 0 || result.ActionFailed > 0 {
		return "partial"
	}
	return "completed"
}

func finalizeScheduledBatch(ctx workflow.Context, input SchedulerWorkflowInput, result *SchedulerWorkflowResult) error {
	batchResult := &BatchPortScanResult{
		Targets:        input.BatchInput.Targets,
		Ports:          input.BatchInput.Ports,
		MaxConcurrency: input.BatchInput.MaxConcurrency,
		ChunkPrefix:    input.BatchInput.ChunkPrefix,
		MaxAttempts:    input.BatchInput.MaxAttempts,
		RetryDelay:     input.BatchInput.RetryDelaySeconds,
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

func plannedDAGFollowUpWorkItemFromScheduler(input SchedulerWorkflowInput, parent data.WorkItem) data.WorkItem {
	return plannedDAGFollowUpWorkItem(input, parent.Target, parent.ID, 1, input.BatchInput.PlannedDAGMaxIterations, parent.Priority)
}

func actionWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	switch node.Artifact {
	case "spray":
		return sprayShardWorkItemsFromDAGNode(input, parent, node, iteration, maxIterations)
	case "nuclei":
		return nucleiGroupWorkItemsFromDAGNode(input, parent, node, iteration, maxIterations)
	default:
		item := actionWorkItemFromDAGNode(input, parent, node, iteration, maxIterations)
		if item.ID == "" {
			return nil
		}
		return []data.WorkItem{item}
	}
}

func actionWorkItemFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) data.WorkItem {
	itemType := actionWorkItemType(node.Artifact)
	if itemType == "" {
		return data.WorkItem{}
	}
	return actionWorkItemFromDAGNodeInput(input, parent, node, mapAnyToInterface(node.Input), iteration, maxIterations, 0)
}

func actionWorkItemFromDAGNodeInput(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, actionInput map[string]interface{}, iteration, maxIterations, shardIndex int) data.WorkItem {
	itemType := actionWorkItemType(node.Artifact)
	if itemType == "" {
		return data.WorkItem{}
	}
	target := node.Target
	if target == "" {
		target = parent.Target
	}
	idParts := []string{"work_item", input.BatchID, itemType, node.ID}
	if shardIndex > 0 {
		idParts = append(idParts, fmt.Sprintf("shard-%d", shardIndex))
	}
	return data.WorkItem{
		ID:          data.GenerateID(idParts...),
		CampaignID:  input.BatchInput.CampaignID,
		BatchID:     input.BatchID,
		ParentID:    parent.ID,
		Type:        itemType,
		Target:      target,
		Artifact:    node.Artifact,
		Queue:       schedulerQueueForType(itemType),
		Input:       mustMarshal(actionWorkItemInputFromDAGNode(node, target, actionInput, iteration, maxIterations, shardIndex)),
		Priority:    node.Priority,
		Status:      "pending",
		MaxAttempts: input.BatchInput.MaxAttempts,
	}
}

func sprayShardWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	baseInput := mapAnyToInterface(node.Input)
	baseURLs := stringSliceFromActionInput(baseInput, "base_urls")
	checkURLs := stringSliceFromActionInput(baseInput, "urls")
	wordlist := stringSliceFromActionInput(baseInput, "wordlist")
	if len(wordlist) == 0 && stringFromActionInput(baseInput, "wordlist_mode") == "full" {
		wordlist = artifact.FullSprayWordlist()
		delete(baseInput, "wordlist_mode")
	}

	baseURLChunks := chunkStrings(baseURLs, sprayShardBaseURLSize(input))
	if len(baseURLChunks) == 0 {
		baseURLChunks = [][]string{nil}
	}
	checkURLChunks := chunkStrings(checkURLs, sprayShardBaseURLSize(input))
	if len(checkURLChunks) == 0 {
		checkURLChunks = [][]string{nil}
	}
	wordChunks := chunkStrings(wordlist, sprayShardWordSize(input))
	if len(wordChunks) == 0 {
		wordChunks = [][]string{nil}
	}

	var items []data.WorkItem
	shardIndex := 1
	if len(baseURLs) > 0 {
		for _, urlChunk := range baseURLChunks {
			for _, wordChunk := range wordChunks {
				shardInput := copyActionInput(baseInput)
				shardInput["base_urls"] = urlChunk
				if len(wordChunk) > 0 {
					shardInput["wordlist"] = wordChunk
				}
				shardInput["_shard"] = map[string]interface{}{
					"type":       "spray",
					"index":      shardIndex,
					"base_urls":  len(urlChunk),
					"word_count": len(wordChunk),
				}
				items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, shardInput, iteration, maxIterations, shardIndex))
				shardIndex++
			}
		}
		return items
	}
	if len(checkURLs) > 0 {
		for _, urlChunk := range checkURLChunks {
			shardInput := copyActionInput(baseInput)
			shardInput["urls"] = urlChunk
			shardInput["_shard"] = map[string]interface{}{"type": "spray_check", "index": shardIndex, "urls": len(urlChunk)}
			items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, shardInput, iteration, maxIterations, shardIndex))
			shardIndex++
		}
		return items
	}
	item := actionWorkItemFromDAGNodeInput(input, parent, node, baseInput, iteration, maxIterations, 0)
	if item.ID == "" {
		return nil
	}
	return []data.WorkItem{item}
}

func nucleiGroupWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	baseInput := mapAnyToInterface(node.Input)
	targets := stringSliceFromActionInput(baseInput, "targets")
	ids := stringSliceFromActionInput(baseInput, "ids")
	tags := stringSliceFromActionInput(baseInput, "tags")
	targetChunks := chunkStrings(targets, nucleiGroupTargetSize(input))
	if len(targetChunks) == 0 {
		targetChunks = [][]string{nil}
	}
	templateChunks := chunkStrings(ids, nucleiGroupTemplateSize(input))
	templateKey := "ids"
	if len(templateChunks) == 0 {
		templateChunks = chunkStrings(tags, nucleiGroupTemplateSize(input))
		templateKey = "tags"
	}
	if len(templateChunks) == 0 {
		templateChunks = [][]string{nil}
	}

	var items []data.WorkItem
	shardIndex := 1
	for _, targetChunk := range targetChunks {
		for _, templateChunk := range templateChunks {
			groupInput := copyActionInput(baseInput)
			if len(targetChunk) > 0 {
				groupInput["targets"] = targetChunk
			}
			if len(templateChunk) > 0 {
				groupInput[templateKey] = templateChunk
			}
			groupInput["_shard"] = map[string]interface{}{
				"type":      "nuclei",
				"index":     shardIndex,
				"targets":   len(targetChunk),
				"templates": len(templateChunk),
				"filter":    templateKey,
			}
			items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, groupInput, iteration, maxIterations, shardIndex))
			shardIndex++
		}
	}
	return items
}

func actionWorkItemInputFromDAGNode(node planner.DAGPlanNode, target string, actionInput map[string]interface{}, iteration, maxIterations, shardIndex int) schedulerWorkItemInput {
	return schedulerWorkItemInput{
		Target:        target,
		ActionInput:   actionInput,
		NodeID:        node.ID,
		Reason:        node.Reason,
		Risk:          node.Risk,
		Cost:          node.Cost,
		DedupKey:      node.DedupKey,
		RunIf:         node.RunIf,
		Iteration:     iteration,
		MaxIterations: maxIterations,
		ShardIndex:    shardIndex,
	}
}

func actionWorkItemType(artifactName string) string {
	switch artifactName {
	case "fingers":
		return "fingers_action"
	case "spray":
		return "spray_shard"
	case "nuclei":
		return "nuclei_group"
	default:
		return ""
	}
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
	return upsertBatchWorkItem(ctx, plannedDAGFollowUpWorkItem(input, item.Target, item.ID, iteration+1, maxIterations, item.Priority))
}

func plannedDAGFollowUpWorkItem(input SchedulerWorkflowInput, target, parentID string, iteration, maxIterations, priority int) data.WorkItem {
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
		Priority:    priority,
		Status:      "pending",
		MaxAttempts: 1,
	}
}

func minPositive(value, fallback int) int {
	if value > 0 && value < fallback {
		return value
	}
	return fallback
}

func maxPositive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func sprayShardBaseURLSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.SprayShardBaseURLs > 0 {
		return input.BatchInput.SprayShardBaseURLs
	}
	return 1
}

func sprayShardWordSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.SprayShardWords > 0 {
		return input.BatchInput.SprayShardWords
	}
	return 500
}

func nucleiGroupTargetSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.NucleiGroupTargets > 0 {
		return input.BatchInput.NucleiGroupTargets
	}
	return 25
}

func nucleiGroupTemplateSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.NucleiGroupTemplates > 0 {
		return input.BatchInput.NucleiGroupTemplates
	}
	return 80
}

func chunkStrings(values []string, size int) [][]string {
	values = uniqueNonEmpty(values)
	if len(values) == 0 {
		return nil
	}
	if size <= 0 || size >= len(values) {
		return [][]string{values}
	}
	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, append([]string{}, values[start:end]...))
	}
	return chunks
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func copyActionInput(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringSliceFromActionInput(input map[string]interface{}, key string) []string {
	if input == nil {
		return nil
	}
	switch value := input[key].(type) {
	case []string:
		return append([]string{}, value...)
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func stringFromActionInput(input map[string]interface{}, key string) string {
	if input == nil {
		return ""
	}
	value, _ := input[key].(string)
	return value
}

func normalizeBatchPortScanInput(input BatchPortScanInput) BatchPortScanInput {
	if input.Ports == "" {
		input.Ports = "top3"
	}
	if input.MaxConcurrency <= 0 {
		input.MaxConcurrency = 4
	}
	if input.MaxConcurrency > 64 {
		input.MaxConcurrency = 64
	}
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
	if input.PlannedDAGConcurrency <= 0 {
		input.PlannedDAGConcurrency = input.MaxConcurrency
	}
	if input.PlannedDAGConcurrency > 64 {
		input.PlannedDAGConcurrency = 64
	}
	if input.PlannedDAGMaxIterations <= 0 {
		input.PlannedDAGMaxIterations = 5
	}
	if input.PlannedDAGMaxIterations > 20 {
		input.PlannedDAGMaxIterations = 20
	}
	return input
}
