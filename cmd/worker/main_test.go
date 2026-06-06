package main

import (
	"testing"
	"time"

	"github.com/0xrawptr/weave/internal/config"
)

func TestWorkerOptionsForArtifactWorker(t *testing.T) {
	opts := workerOptions(config.WorkerConfig{
		MaxConcurrentActivityTasks:       3,
		MaxConcurrentWorkflowTasks:       1,
		MaxConcurrentActivityTaskPollers: 2,
		MaxConcurrentWorkflowTaskPollers: 1,
		WorkerActivitiesPerSecond:        1.5,
		TaskQueueActivitiesPerSecond:     2.5,
		WorkerStopTimeout:                10 * time.Second,
	}, true)

	if !opts.DisableWorkflowWorker {
		t.Fatal("artifact worker should disable workflow worker")
	}
	if opts.MaxConcurrentActivityExecutionSize != 3 {
		t.Fatalf("activity concurrency = %d", opts.MaxConcurrentActivityExecutionSize)
	}
	if opts.MaxConcurrentWorkflowTaskExecutionSize != 2 {
		t.Fatalf("workflow concurrency = %d", opts.MaxConcurrentWorkflowTaskExecutionSize)
	}
	if opts.MaxConcurrentWorkflowTaskPollers != 2 {
		t.Fatalf("workflow pollers = %d", opts.MaxConcurrentWorkflowTaskPollers)
	}
	if opts.WorkerActivitiesPerSecond != 1.5 {
		t.Fatalf("worker activity rate = %f", opts.WorkerActivitiesPerSecond)
	}
	if opts.TaskQueueActivitiesPerSecond != 2.5 {
		t.Fatalf("task queue activity rate = %f", opts.TaskQueueActivitiesPerSecond)
	}
	if opts.WorkerStopTimeout != 10*time.Second {
		t.Fatalf("worker stop timeout = %s", opts.WorkerStopTimeout)
	}
}
