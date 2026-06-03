package planner

import (
	"context"
	"encoding/json"

	"github.com/0xrawptr/weave/internal/data"
	"go.temporal.io/sdk/activity"
)

const PlanTargetActivityName = "plan_target"
const ClaimActionActivityName = "claim_action"
const CompleteActionActivityName = "complete_action"

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

func (a *Activity) ClaimAction(ctx context.Context, action Action) (bool, error) {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return true, nil
	}
	raw, _ := json.Marshal(action.PersistInput())
	info := activity.GetInfo(ctx)
	return a.planner.repo.ClaimAction(ctx, data.ActionRecord{
		ID:         action.ID,
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
	Error   string `json:"error,omitempty"`
}

func (a *Activity) CompleteAction(ctx context.Context, completion ActionCompletion) error {
	if a == nil || a.planner == nil || a.planner.repo == nil {
		return nil
	}
	return a.planner.repo.CompleteAction(ctx, completion.ID, completion.Success, completion.Error)
}
