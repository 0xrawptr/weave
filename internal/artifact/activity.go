package artifact

import (
	"context"
	"fmt"
	"time"

	"go.temporal.io/sdk/activity"
)

// ActivityResult wraps the output for Temporal activity registration.
type ActivityResult struct {
	Artifact string `json:"artifact"`
	Target   string `json:"target"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Duration int64  `json:"duration_ms"`
}

// ActivityFunc is the signature that all Temporal activities must match.
type ActivityFunc func(ctx context.Context, input Input) (*ActivityResult, error)

// PersistHook is called after successful activity execution to persist results.
type PersistHook func(ctx context.Context, result *ActivityResult) error

// DedupHook checks if the given target+artifact+input has already been processed.
type DedupHook func(ctx context.Context, target, artifact string, input []byte) (bool, error)

// MarkDoneHook marks a target+artifact+input as processed.
type MarkDoneHook func(ctx context.Context, target, artifact string, input []byte) error

// NewActivityFunc creates a named Temporal activity function for the given artifact.
func NewActivityFunc(a Artifact, persist PersistHook, dedup DedupHook, markDone MarkDoneHook) ActivityFunc {
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

		if err := validateInput(a.InputSchema(), input); err != nil {
			return &ActivityResult{
				Artifact: a.Name(),
				Target:   input.Target,
				Success:  false,
				Error:    err.Error(),
			}, nil
		}

		output, err := a.Execute(ctx, input)
		duration := time.Since(start).Milliseconds()

		result := &ActivityResult{
			Artifact: a.Name(),
			Target:   output.Target,
			Success:  output.Success && err == nil,
			Data:     output.Data,
			Duration: duration,
		}

		if output.Error != "" {
			result.Error = output.Error
		}
		if err != nil {
			result.Error = err.Error()
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

func validateInput(schema InputSchema, input Input) error {
	for _, field := range schema.Fields {
		if field.Required && input.Data == nil {
			return fmt.Errorf("required field %q is missing", field.Name)
		}
	}
	return nil
}
