package main

import (
	"context"
	"fmt"
	"log"

	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/config"
	appruntime "github.com/0xrawptr/weave/internal/runtime"
	"github.com/0xrawptr/weave/internal/workflow"

	"go.temporal.io/sdk/client"
	sdkworker "go.temporal.io/sdk/worker"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()

	runtimeApp, err := app.New(ctx, cfg)
	if err != nil {
		log.Fatalf("artifact init: %v", err)
	}

	c, err := client.Dial(client.Options{
		HostPort:  fmt.Sprintf("%s:%d", cfg.Temporal.Host, cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("temporal client: %v", err)
	}
	defer c.Close()

	var workers []sdkworker.Worker
	controlWorker := sdkworker.New(c, cfg.Temporal.TaskQueue, workerOptions(cfg.Temporal.Workers.Control, false))
	appruntime.ConfigureControlWorker(controlWorker, runtimeApp)
	workers = append(workers, controlWorker)

	for _, info := range runtimeApp.Registry.List() {
		taskQueue := workflow.ArtifactTaskQueue(info.Name)
		artifactWorker := sdkworker.New(c, taskQueue, workerOptions(cfg.ArtifactWorkerConfig(info.Name), true))
		appruntime.ConfigureArtifactWorker(artifactWorker, runtimeApp, info.Name)
		workers = append(workers, artifactWorker)
	}

	for _, w := range workers {
		if err := w.Start(); err != nil {
			log.Fatalf("worker start: %v", err)
		}
	}
	log.Printf("control worker started on task queue %q", cfg.Temporal.TaskQueue)
	for _, info := range runtimeApp.Registry.List() {
		log.Printf("artifact worker started: artifact=%s task_queue=%q options=%+v", info.Name, workflow.ArtifactTaskQueue(info.Name), cfg.ArtifactWorkerConfig(info.Name))
	}
	<-sdkworker.InterruptCh()
	log.Println("shutting down workers...")
	for _, w := range workers {
		w.Stop()
	}
	runtimeApp.Close()
}

func workerOptions(cfg config.WorkerConfig, activityOnly bool) sdkworker.Options {
	return sdkworker.Options{
		MaxConcurrentActivityExecutionSize:     cfg.MaxConcurrentActivityTasks,
		MaxConcurrentWorkflowTaskExecutionSize: normalizeWorkflowConcurrency(cfg.MaxConcurrentWorkflowTasks),
		MaxConcurrentActivityTaskPollers:       cfg.MaxConcurrentActivityTaskPollers,
		MaxConcurrentWorkflowTaskPollers:       normalizeWorkflowConcurrency(cfg.MaxConcurrentWorkflowTaskPollers),
		WorkerActivitiesPerSecond:              cfg.WorkerActivitiesPerSecond,
		TaskQueueActivitiesPerSecond:           cfg.TaskQueueActivitiesPerSecond,
		WorkerStopTimeout:                      cfg.WorkerStopTimeout,
		DisableWorkflowWorker:                  activityOnly,
	}
}

func normalizeWorkflowConcurrency(value int) int {
	if value == 1 {
		return 2
	}
	return value
}
