package workflow

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	defaultLongActivityTimeout  = 24 * time.Hour
	maxLongActivityTimeout      = 7 * 24 * time.Hour
	defaultStateActivityTimeout = 30 * time.Second
)

func longActivityTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultLongActivityTimeout
	}
	timeout := time.Duration(seconds) * time.Second
	if timeout > maxLongActivityTimeout {
		return maxLongActivityTimeout
	}
	return timeout
}

func longActivityContext(ctx workflow.Context, timeoutSeconds int) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: longActivityTimeout(timeoutSeconds),
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 1,
		},
	})
}

func artifactActivityContext(ctx workflow.Context, artifactName string, timeoutSeconds int) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		TaskQueue:           ArtifactTaskQueue(artifactName),
		StartToCloseTimeout: longActivityTimeout(timeoutSeconds),
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 1,
		},
	})
}

func shortArtifactActivityContext(ctx workflow.Context, artifactName string, timeout time.Duration, maxAttempts int32) workflow.Context {
	if timeout <= 0 {
		timeout = defaultStateActivityTimeout
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		TaskQueue:           ArtifactTaskQueue(artifactName),
		StartToCloseTimeout: timeout,
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: maxAttempts,
		},
	})
}
