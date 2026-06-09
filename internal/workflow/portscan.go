package workflow

import (
	"fmt"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/workflow"
)

// PortScanInput is a gogo-only scan without vulnerability detection.
type PortScanInput struct {
	IP                     string `json:"ip"`
	CampaignID             string `json:"campaign_id,omitempty"`
	Ports                  string `json:"ports"`
	ActivityTimeoutSeconds int    `json:"activity_timeout_seconds,omitempty"`
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
	ctx = artifactActivityContext(ctx, "gogo", input.ActivityTimeoutSeconds)

	if input.Ports == "" {
		input.Ports = "top3"
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
			if chunkResult.Error == "" {
				chunkResult.Error = "gogo scan failed"
			}
			result.Results = append(result.Results, chunkResult)
			result.Gogo = &gogoResult
			return result, fmt.Errorf("gogo chunk %s: %s", chunk, chunkResult.Error)
		}
		result.Results = append(result.Results, chunkResult)
		result.Gogo = &gogoResult
	}

	return result, nil
}
