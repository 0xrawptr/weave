package workflow

import (
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// PortScanInput is a gogo-only scan without vulnerability detection.
type PortScanInput struct {
	IP         string `json:"ip"`
	CampaignID string `json:"campaign_id,omitempty"`
	Ports      string `json:"ports"`
}

// PortScanResult contains only the gogo scan results.
type PortScanResult struct {
	IP      string                   `json:"ip"`
	Ports   string                   `json:"ports"`
	Chunks  int                      `json:"chunks"`
	Results []PortScanChunkResult    `json:"results,omitempty"`
	Gogo    *artifact.ActivityResult `json:"gogo,omitempty"`
}

type PortScanChunkResult struct {
	Chunk   string                   `json:"chunk"`
	Success bool                     `json:"success"`
	Error   string                   `json:"error,omitempty"`
	Gogo    *artifact.ActivityResult `json:"gogo,omitempty"`
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

	chunks := splitCIDR(input.IP)
	result := &PortScanResult{IP: input.IP, Ports: input.Ports, Chunks: len(chunks)}

	for i, chunk := range chunks {
		chunkResult := PortScanChunkResult{Chunk: chunk}
		var gogoResult artifact.ActivityResult
		err := workflow.ExecuteActivity(ctx, "gogo", artifact.Input{
			Target:     input.IP,
			CampaignID: input.CampaignID,
			Data: mustMarshal(map[string]interface{}{
				"ip":          chunk,
				"ports":       input.Ports,
				"chunk_idx":   i + 1,
				"chunk_total": len(chunks),
			}),
		}).Get(ctx, &gogoResult)
		chunkResult.Gogo = &gogoResult
		chunkResult.Success = err == nil && gogoResult.Success
		if err != nil {
			chunkResult.Error = err.Error()
			result.Results = append(result.Results, chunkResult)
			return result, err
		}
		if !gogoResult.Success {
			chunkResult.Error = gogoResult.Error
		}
		result.Results = append(result.Results, chunkResult)
		result.Gogo = &gogoResult
	}

	return result, nil
}
