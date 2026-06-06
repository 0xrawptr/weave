package workflow

import (
	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/workflow"
)

type ActionWorkflowInput struct {
	Artifact               string                 `json:"artifact"`
	Target                 string                 `json:"target"`
	CampaignID             string                 `json:"campaign_id,omitempty"`
	Input                  map[string]interface{} `json:"input"`
	ActivityTimeoutSeconds int                    `json:"activity_timeout_seconds,omitempty"`
}

// ActionWorkflow executes one planner/manual action. It is the bridge from
// hard-coded workflows toward planner-driven scheduling.
func ActionWorkflow(ctx workflow.Context, input ActionWorkflowInput) (*artifact.ActivityResult, error) {
	ctx = artifactActivityContext(ctx, input.Artifact, input.ActivityTimeoutSeconds)

	var result artifact.ActivityResult
	err := workflow.ExecuteActivity(ctx, input.Artifact, artifact.Input{
		Target:     input.Target,
		CampaignID: input.CampaignID,
		Data:       mustMarshal(input.Input),
	}).Get(ctx, &result)
	if err != nil {
		return &result, err
	}
	return &result, nil
}
