package planner

import (
	"context"
	"encoding/json"

	"github.com/0xrawptr/weave/internal/data"
	"go.temporal.io/sdk/activity"
)

const PlanTargetActivityName = "plan_target"
const PlanDAGTargetActivityName = "plan_dag_target"
const ClaimActionActivityName = "claim_action"
const CompleteActionActivityName = "complete_action"
const EvaluateConditionActivityName = "evaluate_condition"
const UpsertBatchRunActivityName = "upsert_batch_run"
const UpsertBatchChunkActivityName = "upsert_batch_chunk"
const UpsertWorkItemActivityName = "upsert_work_item"
const UpsertWorkItemsActivityName = "upsert_work_items"
const ClaimWorkItemActivityName = "claim_work_item"
const SetWorkItemStatusActivityName = "set_work_item_status"
const HeartbeatWorkItemActivityName = "heartbeat_work_item"
const GetCampaignStatusActivityName = "get_campaign_status"
const WorkItemSummaryActivityName = "work_item_summary"
const RecoverStaleWorkItemsActivityName = "recover_stale_work_items"
const RequeueRetryWaitingWorkItemsActivityName = "requeue_retry_waiting_work_items"

type Activity struct {
	planner *Planner
}

func NewActivity(repo *data.Repository) *Activity {
	return &Activity{planner: New(repo)}
}

func (a *Activity) PlanTarget(ctx context.Context, target string) ([]Action, error) {
	if a == nil || a.planner == nil {
		return nil, nil
	}
	return a.planner.PlanForTarget(ctx, target)
}

type PlanDAGRequest struct {
	Target     string `json:"target"`
	CampaignID string `json:"campaign_id,omitempty"`
}

func (a *Activity) PlanDAGTarget(ctx context.Context, request PlanDAGRequest) (*DAGPlan, error) {
	if a == nil || a.planner == nil {
		return nil, nil
	}
	return a.planner.PlanDAGForTarget(ctx, request.Target, request.CampaignID)
}

func (a *Activity) ClaimAction(ctx context.Context, action Action) (bool, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return true, nil
	}
	raw, _ := json.Marshal(action.PersistInput())
	info := activity.GetInfo(ctx)
	workflowID := action.WorkflowID
	if workflowID == "" {
		workflowID = info.WorkflowExecution.ID
	}
	return a.planner.repo.ClaimAction(ctx, data.ActionRecord{
		ID:         action.ID,
		CampaignID: action.CampaignID,
		Target:     action.Target,
		Artifact:   action.Artifact,
		Input:      raw,
		Priority:   action.Priority,
		Reason:     action.Reason,
		Status:     "running",
		WorkflowID: workflowID,
	})
}

type ActionCompletion struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Status  string `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (a *Activity) CompleteAction(ctx context.Context, completion ActionCompletion) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	if completion.Status != "" {
		return a.planner.repo.SetActionStatus(ctx, completion.ID, completion.Status, completion.Error)
	}
	return a.planner.repo.CompleteAction(ctx, completion.ID, completion.Success, completion.Error)
}

type ConditionRequest struct {
	Target     string           `json:"target"`
	CampaignID string           `json:"campaign_id,omitempty"`
	All        []AssetCondition `json:"all,omitempty"`
	Any        []AssetCondition `json:"any,omitempty"`
}

type AssetCondition struct {
	Type     string `json:"type,omitempty"`
	Source   string `json:"source,omitempty"`
	Status   string `json:"status,omitempty"`
	MinCount int    `json:"min_count,omitempty"`
}

type ConditionResult struct {
	OK      bool                  `json:"ok"`
	Counts  []AssetConditionCount `json:"counts,omitempty"`
	Message string                `json:"message,omitempty"`
}

type AssetConditionCount struct {
	Condition AssetCondition `json:"condition"`
	Count     int            `json:"count"`
	OK        bool           `json:"ok"`
}

func (a *Activity) EvaluateCondition(ctx context.Context, request ConditionRequest) (ConditionResult, error) {
	if request.Target == "" {
		return ConditionResult{OK: false, Message: "target is required"}, nil
	}
	if len(request.All) == 0 && len(request.Any) == 0 {
		return ConditionResult{OK: true}, nil
	}
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return ConditionResult{OK: true}, nil
	}

	result := ConditionResult{OK: true}
	for _, condition := range request.All {
		count, err := a.planner.repo.CountAssetsInCampaign(ctx, request.Target, request.CampaignID, condition.Type, condition.Source, condition.Status)
		if err != nil {
			return result, err
		}
		ok := count >= minCount(condition.MinCount)
		result.Counts = append(result.Counts, AssetConditionCount{Condition: condition, Count: count, OK: ok})
		if !ok {
			result.OK = false
		}
	}
	if len(request.Any) == 0 {
		return result, nil
	}

	anyOK := false
	for _, condition := range request.Any {
		count, err := a.planner.repo.CountAssetsInCampaign(ctx, request.Target, request.CampaignID, condition.Type, condition.Source, condition.Status)
		if err != nil {
			return result, err
		}
		ok := count >= minCount(condition.MinCount)
		result.Counts = append(result.Counts, AssetConditionCount{Condition: condition, Count: count, OK: ok})
		if ok {
			anyOK = true
		}
	}
	result.OK = result.OK && anyOK
	return result, nil
}

func minCount(value int) int {
	if value <= 0 {
		return 1
	}
	return value
}

func (a *Activity) UpsertBatchRun(ctx context.Context, run data.BatchRun) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.UpsertBatchRun(ctx, run)
}

func (a *Activity) UpsertBatchChunk(ctx context.Context, chunk data.BatchChunk) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.UpsertBatchChunk(ctx, chunk)
}

func (a *Activity) UpsertWorkItem(ctx context.Context, item data.WorkItem) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.UpsertWorkItem(ctx, item)
}

func (a *Activity) UpsertWorkItems(ctx context.Context, items []data.WorkItem) error {
	if a == nil || a.planner == nil || a.planner.repo == nil || len(items) == 0 {
		return nil
	}
	return a.planner.repo.UpsertWorkItems(ctx, items)
}

func (a *Activity) ClaimWorkItem(ctx context.Context, request data.WorkItemClaimRequest) (data.WorkItem, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return data.WorkItem{}, nil
	}
	item, err := a.planner.repo.ClaimWorkItem(ctx, request)
	if err != nil || item == nil {
		return data.WorkItem{}, err
	}
	return *item, nil
}

type WorkItemStatusUpdate struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	WorkflowID       string `json:"workflow_id,omitempty"`
	Error            string `json:"error,omitempty"`
	IncrementAttempt bool   `json:"increment_attempt,omitempty"`
}

func (a *Activity) SetWorkItemStatus(ctx context.Context, update WorkItemStatusUpdate) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.SetWorkItemStatus(ctx, update.ID, update.Status, update.WorkflowID, update.Error, update.IncrementAttempt)
}

func (a *Activity) HeartbeatWorkItem(ctx context.Context, request data.WorkItemHeartbeatRequest) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.HeartbeatWorkItem(ctx, request)
}

func (a *Activity) GetCampaignStatus(ctx context.Context, campaignID string) (string, error) {
	if campaignID == "" || a == nil || a.planner == nil || a.planner.repo == nil {
		return "active", nil
	}
	campaign, err := a.planner.repo.GetCampaign(ctx, campaignID)
	if err != nil {
		return "active", nil
	}
	if campaign.Status == "" {
		return "active", nil
	}
	return campaign.Status, nil
}

type WorkItemSummaryRequest struct {
	CampaignID string `json:"campaign_id,omitempty"`
	BatchID    string `json:"batch_id,omitempty"`
	Type       string `json:"type,omitempty"`
	Artifact   string `json:"artifact,omitempty"`
}

type WorkItemSummary struct {
	ByStatus map[string]int `json:"by_status"`
	Total    int            `json:"total"`
}

func (a *Activity) WorkItemSummary(ctx context.Context, request WorkItemSummaryRequest) (WorkItemSummary, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return WorkItemSummary{}, nil
	}
	counts, err := a.planner.repo.CountWorkItemsByStatus(ctx, request.CampaignID, request.BatchID, request.Type, request.Artifact)
	if err != nil {
		return WorkItemSummary{}, err
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	return WorkItemSummary{ByStatus: counts, Total: total}, nil
}

type RecoverStaleWorkItemsRequest struct {
	Filter data.WorkItemFilter `json:"filter"`
	Limit  int                 `json:"limit,omitempty"`
}

func (a *Activity) RecoverStaleWorkItems(ctx context.Context, request RecoverStaleWorkItemsRequest) (data.WorkItemBulkResult, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return data.WorkItemBulkResult{}, nil
	}
	return a.planner.repo.RecoverStaleWorkItems(ctx, request.Filter, request.Limit)
}

type RequeueRetryWaitingWorkItemsRequest struct {
	Filter        data.WorkItemFilter `json:"filter"`
	MinAgeSeconds int                 `json:"min_age_seconds,omitempty"`
	Limit         int                 `json:"limit,omitempty"`
}

func (a *Activity) RequeueRetryWaitingWorkItems(ctx context.Context, request RequeueRetryWaitingWorkItemsRequest) (data.WorkItemBulkResult, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return data.WorkItemBulkResult{}, nil
	}
	return a.planner.repo.RequeueRetryWaitingWorkItems(ctx, request.Filter, request.MinAgeSeconds, request.Limit)
}
