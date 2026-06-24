package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/contextx"
	"go.temporal.io/sdk/activity"
)

// ActivityResult wraps the output for Temporal activity registration.
type ActivityResult struct {
	Artifact string          `json:"artifact"`
	Target   string          `json:"target"`
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Data     []byte          `json:"data,omitempty"`
	Duration int64           `json:"duration_ms"`
	Stats    []ExecutionStat `json:"stats,omitempty"`
}

// ActivityFunc is the signature that all Temporal activities must match.
type ActivityFunc func(ctx context.Context, input Input) (*ActivityResult, error)

// PersistHook is called after successful activity execution to persist results.
type PersistHook func(ctx context.Context, result *ActivityResult) error

// DedupHook checks if the given target+artifact+input has already been processed.
type DedupHook func(ctx context.Context, target, artifact string, input []byte) (bool, error)

// MarkDoneHook marks a target+artifact+input as processed.
type MarkDoneHook func(ctx context.Context, target, artifact string, input []byte) error

// RawEventHandler stores raw artifact output before any transformation.
type RawEventHandler func(ctx context.Context, artifact, target, workflowID, campaignID string, data []byte)

// StatsHook stores normalized SDK execution counters emitted by artifacts.
type StatsHook func(ctx context.Context, artifact, target, workflowID, campaignID string, stats []ExecutionStat) error

// WorkItemHeartbeatHook mirrors Temporal activity heartbeat state to the durable scheduler ledger.
type WorkItemHeartbeatHook func(ctx context.Context, workItemID, workflowID string, leaseSeconds int) error

// NewActivityFunc creates a named Temporal activity function for the given artifact.
func NewActivityFunc(a Artifact, persist PersistHook, dedup DedupHook, markDone MarkDoneHook, rawEvent RawEventHandler, statsHook StatsHook, heartbeatHook WorkItemHeartbeatHook) ActivityFunc {
	return func(ctx context.Context, input Input) (*ActivityResult, error) {
		logger := activity.GetLogger(ctx)
		logger.Info("artifact started", "artifact", a.Name(), "target", input.Target)

		// Deduplication check
		if dedup != nil {
			if isDup, _ := dedup(ctx, input.Target, a.Name(), input.Data); isDup {
				logger.Info("skipping duplicate", "artifact", a.Name(), "target", input.Target)
				return &ActivityResult{Artifact: a.Name(), Target: input.Target, Success: true}, nil
			}
		}

		start := time.Now()
		if input.WorkflowID == "" {
			input.WorkflowID = activity.GetInfo(ctx).WorkflowExecution.ID
		}
		stopHeartbeat := startActivityHeartbeat(ctx, a.Name(), input.Target, input, start, heartbeatHook)
		defer stopHeartbeat()

		if err := validateInput(a.InputSchema(), input); err != nil {
			return &ActivityResult{
				Artifact: a.Name(),
				Target:   input.Target,
				Success:  false,
				Error:    err.Error(),
			}, nil
		}

		execCtx := contextx.WithCampaignID(ctx, input.CampaignID)
		output, err := a.Execute(execCtx, input)
		duration := time.Since(start).Milliseconds()

		result := &ActivityResult{
			Artifact: a.Name(),
			Target:   output.Target,
			Success:  output.Success && err == nil,
			Data:     output.Data,
			Duration: duration,
			Stats:    output.Stats,
		}

		if output.Error != "" {
			result.Error = output.Error
		}
		if err != nil {
			result.Error = err.Error()
		}
		if len(result.Stats) == 0 {
			result.Stats = []ExecutionStat{fallbackExecutionStat(a.Name(), input.Target, result)}
		}

		if statsHook != nil && len(result.Stats) > 0 {
			wfInfo := activity.GetInfo(ctx)
			if statsErr := statsHook(ctx, a.Name(), input.Target, wfInfo.WorkflowExecution.ID, input.CampaignID, result.Stats); statsErr != nil {
				logger.Error("failed to persist artifact stats", "error", statsErr)
			}
		}

		// Save raw event — untouched artifact output.
		if rawEvent != nil {
			persistData := output.FullData
			if len(persistData) == 0 {
				persistData = output.Data
			}
			if len(persistData) > 0 {
				wfInfo := activity.GetInfo(ctx)
				rawEvent(ctx, a.Name(), input.Target, wfInfo.WorkflowExecution.ID, input.CampaignID, persistData)
			}
		}

		// Persist results — prefer FullData (complete) over Data (summary)
		if persist != nil && result.Success {
			persistData := output.FullData
			if len(persistData) == 0 {
				persistData = output.Data
			}
			if len(persistData) > 0 {
				r := *result
				r.Data = persistData
				if persistErr := persist(ctx, &r); persistErr != nil {
					logger.Error("failed to persist result", "error", persistErr)
				}
			}
		}

		// Mark as processed
		if markDone != nil && result.Success {
			_ = markDone(ctx, input.Target, a.Name(), input.Data)
		}

		logger.Info("artifact completed",
			"artifact", a.Name(),
			"success", result.Success,
			"duration_ms", duration)

		return result, nil
	}
}

func fallbackExecutionStat(artifactName, target string, result *ActivityResult) ExecutionStat {
	stat := ExecutionStat{
		Engine:     artifactName,
		Task:       target,
		Targets:    1,
		Tasks:      1,
		Results:    outputResultCount(result.Data),
		DurationMs: result.Duration,
	}
	if !result.Success {
		stat.Errors = 1
	}
	return stat
}

func outputResultCount(raw []byte) int64 {
	if len(raw) == 0 {
		return 0
	}
	var out struct {
		Total   int64             `json:"total"`
		Count   int64             `json:"count"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0
	}
	switch {
	case out.Total > 0:
		return out.Total
	case out.Count > 0:
		return out.Count
	case len(out.Results) > 0:
		return int64(len(out.Results))
	default:
		return 0
	}
}

func startActivityHeartbeat(ctx context.Context, artifactName, target string, input Input, start time.Time, heartbeatHook WorkItemHeartbeatHook) func() {
	done := make(chan struct{})
	record := func() {
		recordArtifactHeartbeat(ctx, artifactName, target, "running", start, nil)
		if heartbeatHook != nil && input.WorkItemID != "" {
			_ = heartbeatHook(ctx, input.WorkItemID, input.WorkflowID, input.HeartbeatLeaseSeconds)
		}
	}
	record()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				record()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { close(done) }
}

func recordArtifactHeartbeat(ctx context.Context, artifactName, target, stage string, start time.Time, fields map[string]interface{}) {
	defer func() {
		_ = recover()
	}()
	payload := map[string]interface{}{
		"artifact":   artifactName,
		"target":     target,
		"stage":      stage,
		"elapsed_ms": time.Since(start).Milliseconds(),
	}
	for k, v := range fields {
		payload[k] = v
	}
	activity.RecordHeartbeat(ctx, payload)
}

func statHeartbeatFields(latest ExecutionStat, count int) map[string]interface{} {
	return map[string]interface{}{
		"stats_count":       count,
		"stats_engine":      latest.Engine,
		"stats_task":        latest.Task,
		"stats_targets":     latest.Targets,
		"stats_tasks":       latest.Tasks,
		"stats_requests":    latest.Requests,
		"stats_results":     latest.Results,
		"stats_errors":      latest.Errors,
		"stats_duration_ms": latest.DurationMs,
	}
}

func validateInput(schema InputSchema, input Input) error {
	for _, field := range schema.Fields {
		if field.Required && input.Data == nil {
			return fmt.Errorf("required field %q is missing", field.Name)
		}
	}
	return nil
}
