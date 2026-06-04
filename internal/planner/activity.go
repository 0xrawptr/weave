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
	return a.planner.repo.ClaimAction(ctx, data.ActionRecord{
		ID:         action.ID,
		CampaignID: action.CampaignID,
		Target:     action.Target,
		Artifact:   action.Artifact,
		Input:      raw,
		Priority:   action.Priority,
		Reason:     action.Reason,
		Status:     "running",
		WorkflowID: info.WorkflowExecution.ID,
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
