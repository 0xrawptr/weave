package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"

	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/config"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/recovery"
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
	lastReconciled := map[string]time.Time{}
	recoverWorkItems(ctx, runtimeApp, c, cfg, lastReconciled)
	reconcileOpenBatchSchedulers(ctx, runtimeApp, c, cfg, lastReconciled, "startup_reconcile")
	recoveryCtx, stopRecovery := context.WithCancel(ctx)
	defer stopRecovery()
	go runWorkItemRecoveryController(recoveryCtx, runtimeApp, c, cfg)

	var workers []sdkworker.Worker
	controlWorker := sdkworker.New(c, cfg.Temporal.TaskQueue, workerOptions(cfg.Temporal.Workers.Control, false))
	appruntime.ConfigureControlWorker(controlWorker, runtimeApp, c)
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
	stopRecovery()
	recoverWorkItems(ctx, runtimeApp, c, cfg, nil)
	runtimeApp.Close()
}

func recoverWorkItems(ctx context.Context, runtimeApp *app.App, temporalClient client.Client, cfg *config.Config, last map[string]time.Time) {
	if runtimeApp == nil || runtimeApp.Repo == nil {
		return
	}
	result, err := recoverWorkItemsOnce(ctx, runtimeApp, temporalClient)
	if err != nil {
		log.Printf("WARNING: startup work item recovery failed: %v", err)
		return
	}
	if result.Updated > 0 {
		log.Printf("startup work item recovery updated %d item(s)", result.Updated)
		resumeRecoveredSchedulers(ctx, runtimeApp, temporalClient, cfg, result.Batches, "startup_recovery", last)
	}
}

func runWorkItemRecoveryController(ctx context.Context, runtimeApp *app.App, temporalClient client.Client, cfg *config.Config) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	lastReconciled := map[string]time.Time{}
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ticks++
			result, err := recoverWorkItemsOnce(ctx, runtimeApp, temporalClient)
			if err != nil {
				log.Printf("WARNING: work item recovery controller failed: %v", err)
				continue
			}
			if result.Updated > 0 {
				log.Printf("work item recovery controller reclaimed %d item(s)", result.Updated)
				resumeRecoveredSchedulers(ctx, runtimeApp, temporalClient, cfg, result.Batches, "lease_recovery", lastReconciled)
			}
			if ticks%4 == 0 {
				reconcileOpenBatchSchedulers(ctx, runtimeApp, temporalClient, cfg, lastReconciled, "periodic_reconcile")
			}
		}
	}
}

func recoverWorkItemsOnce(ctx context.Context, runtimeApp *app.App, temporalClient client.Client) (data.WorkItemBulkResult, error) {
	if runtimeApp == nil || runtimeApp.Repo == nil {
		return data.WorkItemBulkResult{}, nil
	}
	recoveryResult, err := recovery.RecoverWorkItems(ctx, runtimeApp.Repo, temporalClient, recovery.RecoveryPolicy{
		Limit:                10000,
		RecoverFailures:      true,
		RecoverExpiredLeases: true,
		RequeueRetryWaiting:  true,
		RetryDelaySeconds:    30,
		OnCheckError: func(workflowID, workItemID string, err error) {
			log.Printf("WARNING: temporal orphan check failed: workflow=%s work_item=%s err=%v", workflowID, workItemID, err)
		},
	})
	return recoveryResult.BulkResult(), err
}

func resumeRecoveredSchedulers(ctx context.Context, runtimeApp *app.App, temporalClient client.Client, cfg *config.Config, batches []data.WorkItemBulkBatch, reason string, last map[string]time.Time) {
	if runtimeApp == nil || runtimeApp.Repo == nil || temporalClient == nil || cfg == nil {
		return
	}
	for _, batch := range batches {
		if strings.TrimSpace(batch.BatchID) == "" {
			continue
		}
		if err := resumeRecoveredScheduler(ctx, runtimeApp, temporalClient, cfg, batch.BatchID, reason); err != nil {
			log.Printf("WARNING: resume scheduler after %s failed for batch=%s: %v", reason, batch.BatchID, err)
			continue
		}
		if last != nil {
			last[batch.BatchID] = time.Now()
		}
	}
}

func reconcileOpenBatchSchedulers(ctx context.Context, runtimeApp *app.App, temporalClient client.Client, cfg *config.Config, last map[string]time.Time, reason string) {
	if runtimeApp == nil || runtimeApp.Repo == nil {
		return
	}
	runs, err := runtimeApp.Repo.GetBatchRuns(ctx, "running", 1000, 0)
	if err != nil {
		log.Printf("WARNING: scheduler reconcile list batches failed: %v", err)
		return
	}
	now := time.Now()
	for _, run := range runs {
		if strings.TrimSpace(run.ID) == "" {
			continue
		}
		if last != nil {
			if previous := last[run.ID]; !previous.IsZero() && now.Sub(previous) < 2*time.Minute {
				continue
			}
		}
		summary, err := runtimeApp.Repo.GetWorkItemProgressSummary(ctx, data.WorkItemFilter{BatchID: run.ID})
		if err != nil {
			log.Printf("WARNING: scheduler reconcile summary failed for batch=%s: %v", run.ID, err)
			continue
		}
		pending := summary.ByStatus[data.WorkItemStatusPending] + summary.ByStatus[data.WorkItemStatusRetryWaiting]
		running := summary.ByStatus[data.WorkItemStatusRunning]
		if pending == 0 || running > 0 {
			continue
		}
		if err := resumeRecoveredScheduler(ctx, runtimeApp, temporalClient, cfg, run.ID, reason); err != nil {
			log.Printf("WARNING: scheduler reconcile resume failed for batch=%s: %v", run.ID, err)
			continue
		}
		if last != nil {
			last[run.ID] = now
		}
	}
}

func resumeRecoveredScheduler(ctx context.Context, runtimeApp *app.App, temporalClient client.Client, cfg *config.Config, batchID, reason string) error {
	run, err := runtimeApp.Repo.GetBatchRun(ctx, batchID)
	if err != nil {
		return err
	}
	ports := run.Ports
	if strings.TrimSpace(ports) == "" {
		return fmt.Errorf("batch run has no ports")
	}
	workflowID := fmt.Sprintf("%s-recovery-scheduler", batchID)
	wfRun, err := temporalClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                       workflowID,
		TaskQueue:                cfg.Temporal.TaskQueue,
		WorkflowTaskTimeout:      workflow.ControlWorkflowTaskTimeout,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}, workflow.SchedulerWorkflow, workflow.SchedulerWorkflowInput{
		BatchID: batchID,
		BatchInput: workflow.BatchPortScanInput{
			Targets:       data.SplitList(run.Target, true),
			CampaignID:    run.CampaignID,
			Ports:         ports,
			RunPlannedDAG: true,
		},
		TotalChunks: run.TotalChunks,
	})
	if err != nil {
		return err
	}
	log.Printf("resumed scheduler after %s: batch=%s workflow=%s run=%s", reason, batchID, wfRun.GetID(), wfRun.GetRunID())
	return nil
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
