package workflow

import (
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/workflow"
)

// IPWorkflowInput is the input for the IP scanning workflow.
type IPWorkflowInput struct {
	IP    string `json:"ip"`
	Ports string `json:"ports"`
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
		input.Ports = "top1000"
	}

	result := &IPWorkflowResult{IP: input.IP}

	chunks := splitCIDR(input.IP)
	result.Chunks = len(chunks)

	// Stage 1: gogo per chunk.
	{
		chunkCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 2 * time.Hour,
			HeartbeatTimeout:    30 * time.Second,
		})
		for i, chunk := range chunks {
			var gr artifact.ActivityResult
			err := workflow.ExecuteActivity(chunkCtx, "gogo", artifact.Input{
				Target: input.IP,
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
		postCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 2 * time.Hour,
		})

		var fingersResult artifact.ActivityResult
		err := workflow.ExecuteActivity(postCtx, "fingers", artifact.Input{
			Target: input.IP,
			Data: mustMarshal(map[string]interface{}{
				"mode": "http_match",
			}),
		}).Get(postCtx, &fingersResult)
		if err == nil {
			result.Fingers = &fingersResult
		}

		var nucleiResult artifact.ActivityResult
		err = workflow.ExecuteActivity(postCtx, "nuclei", artifact.Input{
			Target: input.IP,
			Data:   mustMarshal(map[string]interface{}{}),
		}).Get(postCtx, &nucleiResult)
		if err == nil && nucleiResult.Success {
			result.Nuclei = &nucleiResult
		}
	}

	return result, nil
}
