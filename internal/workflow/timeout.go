package workflow

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	defaultLongActivityTimeout  = 2 * time.Hour
	defaultSprayActivityTimeout = 30 * time.Minute
	maxLongActivityTimeout      = 6 * time.Hour
	defaultHeartbeatTimeout     = 60 * time.Second
	defaultStateActivityTimeout = 30 * time.Second
	ControlWorkflowTaskTimeout  = time.Minute
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

func artifactActivityContext(ctx workflow.Context, artifactName string, timeoutSeconds int) workflow.Context {
	startToClose := longActivityTimeout(timeoutSeconds)
	if timeoutSeconds <= 0 && artifactName == "spray" {
		startToClose = defaultSprayActivityTimeout
	}
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		TaskQueue:           ArtifactTaskQueue(artifactName),
		StartToCloseTimeout: startToClose,
		HeartbeatTimeout:    defaultHeartbeatTimeout,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 1,
		},
	})
}
