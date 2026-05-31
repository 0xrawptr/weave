package workflow

import (
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
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
}

// IPWorkflow orchestrates IP-based asset discovery.
// Stage 1: gogo port scan with fingerprint
// Stage 2: fingers web fingerprint on discovered HTTP services
// Stage 3: neutron vuln scan on discovered services
func IPWorkflow(ctx workflow.Context, input IPWorkflowInput) (*IPWorkflowResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 2,
		},
	})

	if input.Ports == "" {
		input.Ports = "top1000"
	}

	result := &IPWorkflowResult{IP: input.IP}

	// Stage 1: gogo port scan
	var gogoResult artifact.ActivityResult
	err := workflow.ExecuteActivity(ctx, "gogo", artifact.Input{
		Target: input.IP,
		Data: mustMarshal(map[string]interface{}{
			"ip":    input.IP,
			"ports": input.Ports,
		}),
	}).Get(ctx, &gogoResult)
	if err != nil {
		return result, err
	}
	result.Gogo = &gogoResult

	webURLs := extractWebURLs(gogoResult)

	if len(webURLs) > 0 {
		// Stage 2: fingers fingerprint
		var fingersResult artifact.ActivityResult
		err = workflow.ExecuteActivity(ctx, "fingers", artifact.Input{
			Target: input.IP,
			Data: mustMarshal(map[string]interface{}{
				"mode": "http_match",
				"urls": webURLs,
			}),
		}).Get(ctx, &fingersResult)
		if err == nil {
			result.Fingers = &fingersResult
		}

		// Stage 3: neutron vuln scan
		for _, url := range webURLs {
			var neutronResult artifact.ActivityResult
			err = workflow.ExecuteActivity(ctx, "neutron", artifact.Input{
				Target: input.IP,
				Data: mustMarshal(map[string]interface{}{
					"target": url,
				}),
			}).Get(ctx, &neutronResult)
			if err == nil && neutronResult.Success {
				result.Neutron = &neutronResult
			}
		}
	}

	return result, nil
}
