package workflow

import (
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/chainreactors/utils"
	"go.temporal.io/sdk/workflow"
)

// IPWorkflowInput is the input for the IP scanning workflow.
type IPWorkflowInput struct {
	IP    string `json:"ip"`
	Ports string `json:"ports"` // e.g. "80,443,8000-9000" or "top1000"
}

// IPWorkflowResult aggregates results from the IP scan pipeline.
type IPWorkflowResult struct {
	IP      string                   `json:"ip"`
	Gogo    *artifact.ActivityResult `json:"gogo,omitempty"`
	Fingers *artifact.ActivityResult `json:"fingers,omitempty"`
	Neutron *artifact.ActivityResult `json:"neutron,omitempty"`
	Chunks  int                      `json:"chunks"`
}

// IPWorkflow orchestrates IP-based asset discovery.
// Large CIDRs are split into /24 chunks for granular retry.
// Stage 1: gogo port scan per chunk → persists to DB
// Stage 2: fingers queries DB for web URLs, fingerprints them
// Stage 3: neutron queries DB for web URLs, scans for vulnerabilities
func IPWorkflow(ctx workflow.Context, input IPWorkflowInput) (*IPWorkflowResult, error) {
	if input.Ports == "" {
		input.Ports = "top1000"
	}

	result := &IPWorkflowResult{IP: input.IP}

	chunks := splitCIDR(input.IP)
	result.Chunks = len(chunks)

	// Stage 1: gogo per chunk — each chunk is an independent activity.
	// Crashed chunks are retried individually by Temporal.
	{
		chunkCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 2 * time.Hour,
			HeartbeatTimeout:    30 * time.Second,
		})
		for _, chunk := range chunks {
			var gr artifact.ActivityResult
			err := workflow.ExecuteActivity(chunkCtx, "gogo", artifact.Input{
				Target: input.IP,
				Data: mustMarshal(map[string]interface{}{
					"ip":    chunk,
					"ports": input.Ports,
				}),
			}).Get(chunkCtx, &gr)
			if err != nil {
				return result, fmt.Errorf("gogo chunk %s: %w", chunk, err)
			}
			result.Gogo = &gr
		}
	}

	// Stage 2 & 3: fingers + neutron run once after all chunks.
	// They query DB (via URLResolver) for all gogo results under input.IP.
	{
		postCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 30 * time.Minute,
			HeartbeatTimeout:    30 * time.Second,
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

		var neutronResult artifact.ActivityResult
		err = workflow.ExecuteActivity(postCtx, "neutron", artifact.Input{
			Target: input.IP,
			Data:   mustMarshal(map[string]interface{}{"target": input.IP}),
		}).Get(postCtx, &neutronResult)
		if err == nil && neutronResult.Success {
			result.Neutron = &neutronResult
		}
	}

	return result, nil
}

// splitCIDR splits a CIDR into /24 chunks (or smaller if the original mask is > 24).
func splitCIDR(target string) []string {
	cidr := utils.ParseCIDR(target)
	if cidr == nil {
		return []string{target}
	}
	if cidr.Mask > 24 {
		return []string{target} // /24 or smaller, scan directly
	}
	chunks, err := cidr.Split(24)
	if err != nil {
		return []string{target}
	}
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = c.String()
	}
	return out
}
