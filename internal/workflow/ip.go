package workflow

import (
	"fmt"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/workflow"
)

// IPWorkflowInput is the input for the IP scanning workflow.
type IPWorkflowInput struct {
	IP                     string `json:"ip"`
	CampaignID             string `json:"campaign_id,omitempty"`
	Ports                  string `json:"ports"`
	ActivityTimeoutSeconds int    `json:"activity_timeout_seconds,omitempty"`
}

// IPWorkflowResult aggregates results from the IP scan pipeline.
type IPWorkflowResult struct {
	IP      string                   `json:"ip"`
	Gogo    *artifact.ActivityResult `json:"gogo,omitempty"`
	Fingers *artifact.ActivityResult `json:"fingers,omitempty"`
	Nuclei  *artifact.ActivityResult `json:"nuclei,omitempty"`
	Chunks  int                      `json:"chunks"`
}

// IPWorkflow orchestrates IP-based asset discovery.
func IPWorkflow(ctx workflow.Context, input IPWorkflowInput) (*IPWorkflowResult, error) {
	if input.Ports == "" {
		input.Ports = "top3"
	}

	result := &IPWorkflowResult{IP: input.IP}

	chunks := splitCIDR(input.IP)
	result.Chunks = len(chunks)

	// Stage 1: gogo per chunk.
	{
		chunkCtx := artifactActivityContext(ctx, "gogo", input.ActivityTimeoutSeconds)
		for i, chunk := range chunks {
			var gr artifact.ActivityResult
			err := workflow.ExecuteActivity(chunkCtx, "gogo", artifact.Input{
				Target:     input.IP,
				CampaignID: input.CampaignID,
				Data: mustMarshal(map[string]interface{}{
					"ip":          chunk,
					"ports":       input.Ports,
					"chunk_idx":   i + 1,
					"chunk_total": len(chunks),
				}),
			}).Get(chunkCtx, &gr)
			if err != nil {
				return result, fmt.Errorf("gogo chunk %s: %w", chunk, err)
			}
			result.Gogo = &gr
		}
	}

	// Stage 2 & 3: fingers + nuclei run after all chunks.
	{
		var fingersResult artifact.ActivityResult
		fingersCtx := artifactActivityContext(ctx, "fingers", input.ActivityTimeoutSeconds)
		err := workflow.ExecuteActivity(fingersCtx, "fingers", artifact.Input{
			Target:     input.IP,
			CampaignID: input.CampaignID,
			Data: mustMarshal(map[string]interface{}{
				"mode": "http_match",
			}),
		}).Get(fingersCtx, &fingersResult)
		if err == nil {
			result.Fingers = &fingersResult
		}

		var nucleiResult artifact.ActivityResult
		nucleiCtx := artifactActivityContext(ctx, "nuclei", input.ActivityTimeoutSeconds)
		err = workflow.ExecuteActivity(nucleiCtx, "nuclei", artifact.Input{
			Target:     input.IP,
			CampaignID: input.CampaignID,
			Data:       mustMarshal(map[string]interface{}{}),
		}).Get(nucleiCtx, &nucleiResult)
		if err == nil && nucleiResult.Success {
			result.Nuclei = &nucleiResult
		}
	}

	return result, nil
}
