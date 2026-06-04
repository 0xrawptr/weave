package workflow

import (
	"fmt"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type BatchPortScanInput struct {
	Targets        []string `json:"targets"`
	CampaignID     string   `json:"campaign_id,omitempty"`
	Ports          string   `json:"ports"`
	MaxConcurrency int      `json:"max_concurrency,omitempty"`
	ChunkPrefix    int      `json:"chunk_prefix,omitempty"`
	MaxAttempts    int      `json:"max_attempts,omitempty"`
}

type BatchPortScanResult struct {
	Targets        []string                   `json:"targets"`
	Ports          string                     `json:"ports"`
	MaxConcurrency int                        `json:"max_concurrency"`
	ChunkPrefix    int                        `json:"chunk_prefix"`
	MaxAttempts    int                        `json:"max_attempts"`
	TotalChunks    int                        `json:"total_chunks"`
	Completed      int                        `json:"completed"`
	Failed         int                        `json:"failed"`
	Chunks         []BatchPortScanChunkResult `json:"chunks,omitempty"`
}

type BatchPortScanChunkResult struct {
	Target     string `json:"target"`
	Chunk      string `json:"chunk"`
	WorkflowID string `json:"workflow_id,omitempty"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

type batchPortScanChunk struct {
	Target string
	Chunk  string
}

type runningPortScanChild struct {
	Index      int
	Target     string
	Chunk      string
	WorkflowID string
	Future     workflow.ChildWorkflowFuture
}

// BatchPortScanWorkflow expands many IP/CIDR targets into scan chunks and runs
// gogo-only child workflows with bounded concurrency.
func BatchPortScanWorkflow(ctx workflow.Context, input BatchPortScanInput) (*BatchPortScanResult, error) {
	if input.Ports == "" {
		input.Ports = "top1000"
	}
	if input.MaxConcurrency <= 0 {
		input.MaxConcurrency = 4
	}
	if input.MaxConcurrency > 64 {
		input.MaxConcurrency = 64
	}
	if input.ChunkPrefix <= 0 || input.ChunkPrefix > 32 {
		input.ChunkPrefix = defaultCIDRChunkPrefix
	}
	if input.MaxAttempts <= 0 {
		input.MaxAttempts = 1
	}
	if input.MaxAttempts > 5 {
		input.MaxAttempts = 5
	}

	chunks := buildPortScanChunks(input.Targets, input.ChunkPrefix)
	result := &BatchPortScanResult{
		Targets:        input.Targets,
		Ports:          input.Ports,
		MaxConcurrency: input.MaxConcurrency,
		ChunkPrefix:    input.ChunkPrefix,
		MaxAttempts:    input.MaxAttempts,
		TotalChunks:    len(chunks),
	}
	if len(chunks) == 0 {
		return result, nil
	}

	parentID := workflow.GetInfo(ctx).WorkflowExecution.ID
	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	if err := upsertPortScanBatchRun(stateCtx, parentID, input, result, "running"); err != nil {
		return result, err
	}
	for _, chunk := range chunks {
		if err := upsertPortScanBatchChunk(stateCtx, parentID, chunk, "", "pending", ""); err != nil {
			return result, err
		}
	}

	for start := 0; start < len(chunks); start += input.MaxConcurrency {
		end := start + input.MaxConcurrency
		if end > len(chunks) {
			end = len(chunks)
		}

		var running []runningPortScanChild
		for i := start; i < end; i++ {
			chunk := chunks[i]
			childID := fmt.Sprintf("%s-portscan-%04d-%s", parentID, i+1, safeWorkflowIDPart(chunk.Chunk))
			if err := upsertPortScanBatchChunk(stateCtx, parentID, chunk, childID, "running", ""); err != nil {
				return result, err
			}
			childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
				WorkflowID: childID,
				RetryPolicy: &temporal.RetryPolicy{
					MaximumAttempts: int32(input.MaxAttempts),
				},
			})
			future := workflow.ExecuteChildWorkflow(childCtx, PortScanWorkflow, PortScanInput{
				IP:         chunk.Chunk,
				CampaignID: input.CampaignID,
				Ports:      input.Ports,
			})
			running = append(running, runningPortScanChild{
				Index:      i,
				Target:     chunk.Target,
				Chunk:      chunk.Chunk,
				WorkflowID: childID,
				Future:     future,
			})
		}

		for _, child := range running {
			chunkResult := BatchPortScanChunkResult{
				Target:     child.Target,
				Chunk:      child.Chunk,
				WorkflowID: child.WorkflowID,
			}
			var portscanResult PortScanResult
			if err := child.Future.Get(ctx, &portscanResult); err != nil {
				chunkResult.Error = err.Error()
				result.Failed++
				if updateErr := upsertPortScanBatchChunk(stateCtx, parentID, batchPortScanChunk{Target: child.Target, Chunk: child.Chunk}, child.WorkflowID, "failed", err.Error()); updateErr != nil {
					return result, updateErr
				}
			} else {
				chunkResult.Success = true
				result.Completed++
				if updateErr := upsertPortScanBatchChunk(stateCtx, parentID, batchPortScanChunk{Target: child.Target, Chunk: child.Chunk}, child.WorkflowID, "completed", ""); updateErr != nil {
					return result, updateErr
				}
			}
			result.Chunks = append(result.Chunks, chunkResult)
		}
	}

	finalStatus := "completed"
	if result.Failed > 0 && result.Completed > 0 {
		finalStatus = "partial"
	} else if result.Failed > 0 {
		finalStatus = "failed"
	}
	if err := upsertPortScanBatchRun(stateCtx, parentID, input, result, finalStatus); err != nil {
		return result, err
	}

	return result, nil
}

func upsertPortScanBatchRun(ctx workflow.Context, batchID string, input BatchPortScanInput, result *BatchPortScanResult, status string) error {
	return workflow.ExecuteActivity(ctx, planner.UpsertBatchRunActivityName, data.BatchRun{
		ID:          batchID,
		CampaignID:  input.CampaignID,
		WorkflowID:  batchID,
		Type:        "batch_portscan",
		Target:      strings.Join(input.Targets, "\n"),
		Ports:       input.Ports,
		Status:      status,
		TotalChunks: result.TotalChunks,
		Completed:   result.Completed,
		Failed:      result.Failed,
	}).Get(ctx, nil)
}

func upsertPortScanBatchChunk(ctx workflow.Context, batchID string, chunk batchPortScanChunk, workflowID, status, errorMessage string) error {
	return workflow.ExecuteActivity(ctx, planner.UpsertBatchChunkActivityName, data.BatchChunk{
		ID:         data.GenerateID("batch_chunk", batchID, chunk.Chunk),
		BatchID:    batchID,
		Target:     chunk.Target,
		Chunk:      chunk.Chunk,
		WorkflowID: workflowID,
		Status:     status,
		Error:      errorMessage,
	}).Get(ctx, nil)
}

func buildPortScanChunks(targets []string, chunkPrefix int) []batchPortScanChunk {
	seen := make(map[string]bool)
	var chunks []batchPortScanChunk
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for _, chunk := range splitCIDRToPrefix(target, chunkPrefix) {
			if seen[chunk] {
				continue
			}
			seen[chunk] = true
			chunks = append(chunks, batchPortScanChunk{Target: target, Chunk: chunk})
		}
	}
	return chunks
}

func safeWorkflowIDPart(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
