package workflow

import (
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type PlannedWorkflowInput struct {
	Target                 string `json:"target"`
	CampaignID             string `json:"campaign_id,omitempty"`
	MaxIterations          int    `json:"max_iterations,omitempty"`
	MaxActions             int    `json:"max_actions,omitempty"`
	ActivityTimeoutSeconds int    `json:"activity_timeout_seconds,omitempty"`
}

type PlannedWorkflowResult struct {
	Target     string           `json:"target"`
	Iterations int              `json:"iterations"`
	Executed   []planner.Action `json:"executed"`
	Skipped    []planner.Action `json:"skipped,omitempty"`
}

// PlannedWorkflow repeatedly plans from the current asset graph and executes
// newly recommended actions. Artifact activities persist raw output and ETL data;
// the next planning activity then sees the updated state.
func PlannedWorkflow(ctx workflow.Context, input PlannedWorkflowInput) (*PlannedWorkflowResult, error) {
	if input.MaxIterations <= 0 {
		input.MaxIterations = 5
	}
	if input.MaxActions <= 0 {
		input.MaxActions = 20
	}

	result := &PlannedWorkflowResult{Target: input.Target}
	executed := make(map[string]bool)

	planCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	})
	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	for iteration := 0; iteration < input.MaxIterations && len(result.Executed) < input.MaxActions; iteration++ {
		result.Iterations = iteration + 1

		var actions []planner.Action
		if err := workflow.ExecuteActivity(planCtx, planner.PlanTargetActivityName, input.Target).Get(planCtx, &actions); err != nil {
			return result, err
		}

		progress := false
		for _, action := range actions {
			if action.ID == "" || executed[action.ID] {
				result.Skipped = append(result.Skipped, action)
				continue
			}
			if action.CampaignID == "" {
				action.CampaignID = input.CampaignID
			}
			if len(result.Executed) >= input.MaxActions {
				return result, nil
			}

			var claimed bool
			if err := workflow.ExecuteActivity(stateCtx, planner.ClaimActionActivityName, action).Get(stateCtx, &claimed); err != nil {
				return result, err
			}
			if !claimed {
				action.Status = "skipped"
				result.Skipped = append(result.Skipped, action)
				executed[action.ID] = true
				continue
			}

			var activityResult artifact.ActivityResult
			actionCtx := artifactActivityContext(ctx, action.Artifact, input.ActivityTimeoutSeconds)
			err := workflow.ExecuteActivity(actionCtx, action.Artifact, artifact.Input{
				Target:     action.Target,
				CampaignID: action.CampaignID,
				Data:       mustMarshal(action.Input),
			}).Get(actionCtx, &activityResult)
			if err != nil {
				_ = workflow.ExecuteActivity(stateCtx, planner.CompleteActionActivityName, planner.ActionCompletion{
					ID:      action.ID,
					Success: false,
					Error:   err.Error(),
				}).Get(stateCtx, nil)
				return result, err
			}

			action.Status = "completed"
			if !activityResult.Success {
				action.Status = "failed"
			}
			if err := workflow.ExecuteActivity(stateCtx, planner.CompleteActionActivityName, planner.ActionCompletion{
				ID:      action.ID,
				Success: activityResult.Success,
				Error:   activityResult.Error,
			}).Get(stateCtx, nil); err != nil {
				return result, err
			}

			executed[action.ID] = true
			result.Executed = append(result.Executed, action)
			progress = true
		}
		if !progress {
			break
		}
	}

	return result, nil
}
