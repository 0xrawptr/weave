package workflow

import (
	"fmt"
	"strings"

	"go.temporal.io/sdk/workflow"
)

type BatchPortScanInput struct {
	Targets        []string `json:"targets"`
	Ports          string   `json:"ports"`
	MaxConcurrency int      `json:"max_concurrency,omitempty"`
	ChunkPrefix    int      `json:"chunk_prefix,omitempty"`
}

type BatchPortScanResult struct {
	Targets        []string                   `json:"targets"`
	Ports          string                     `json:"ports"`
	MaxConcurrency int                        `json:"max_concurrency"`
	ChunkPrefix    int                        `json:"chunk_prefix"`
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

	chunks := buildPortScanChunks(input.Targets, input.ChunkPrefix)
	result := &BatchPortScanResult{
		Targets:        input.Targets,
		Ports:          input.Ports,
		MaxConcurrency: input.MaxConcurrency,
		ChunkPrefix:    input.ChunkPrefix,
		TotalChunks:    len(chunks),
	}
	if len(chunks) == 0 {
		return result, nil
	}

	parentID := workflow.GetInfo(ctx).WorkflowExecution.ID
	for start := 0; start < len(chunks); start += input.MaxConcurrency {
		end := start + input.MaxConcurrency
		if end > len(chunks) {
			end = len(chunks)
		}

		var running []runningPortScanChild
		for i := start; i < end; i++ {
			chunk := chunks[i]
			childID := fmt.Sprintf("%s-portscan-%04d-%s", parentID, i+1, safeWorkflowIDPart(chunk.Chunk))
			childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{WorkflowID: childID})
			future := workflow.ExecuteChildWorkflow(childCtx, PortScanWorkflow, PortScanInput{
				IP:    chunk.Chunk,
				Ports: input.Ports,
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
			} else {
				chunkResult.Success = true
				result.Completed++
			}
			result.Chunks = append(result.Chunks, chunkResult)
		}
	}

	return result, nil
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
