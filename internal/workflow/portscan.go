package workflow

import (
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// PortScanInput is a gogo-only scan without vulnerability detection.
type PortScanInput struct {
	IP    string `json:"ip"`
	Ports string `json:"ports"`
}

// PortScanResult contains only the gogo scan results.
type PortScanResult struct {
	IP   string                   `json:"ip"`
	Gogo *artifact.ActivityResult `json:"gogo,omitempty"`
}

// PortScanWorkflow runs a gogo port scan only (no fingers, no neutron).
func PortScanWorkflow(ctx workflow.Context, input PortScanInput) (*PortScanResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 4 * time.Hour,
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 1, // no retry for long-running scans
		},
	})

	if input.Ports == "" {
		input.Ports = "top1000"
	}

	result := &PortScanResult{IP: input.IP}

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

	return result, nil
}
