package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/etl"
	"github.com/0xrawptr/weave/internal/planner"
	"github.com/0xrawptr/weave/internal/workflow"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
	"go.temporal.io/sdk/activity"
	sdkworker "go.temporal.io/sdk/worker"
)

func ConfigureWorker(w sdkworker.Worker, runtimeApp *app.App) {
	ConfigureControlWorker(w, runtimeApp)
	ConfigureArtifactWorker(w, runtimeApp, "")
}

func ConfigureControlWorker(w sdkworker.Worker, runtimeApp *app.App) {
	repo := runtimeApp.Repo
	registerPlannerActivities(w, repo)
	registerWorkflows(w)
}

func ConfigureArtifactWorker(w sdkworker.Worker, runtimeApp *app.App, onlyArtifact string) {
	repo := runtimeApp.Repo
	persistHook, dedupHook, markDoneHook := buildHooks(repo)
	wireGogoStreaming(runtimeApp)
	registerArtifactActivities(w, runtimeApp, persistHook, dedupHook, markDoneHook, onlyArtifact)
}

func buildHooks(repo *data.Repository) (artifact.PersistHook, artifact.DedupHook, artifact.MarkDoneHook) {
	var persistHook artifact.PersistHook
	var dedupHook artifact.DedupHook
	var markDoneHook artifact.MarkDoneHook

	if repo.Postgres != nil {
		log.Println("normalized persistence enabled through raw-event ETL (PostgreSQL)")
	} else {
		log.Println("persist disabled (PostgreSQL unavailable)")
	}

	if repo.Redis != nil {
		dedupHook = func(ctx context.Context, target, artifactName string, input []byte) (bool, error) {
			if artifactName != "gogo" {
				return false, nil
			}
			return repo.CheckDuplicate(ctx, target, artifactName, input)
		}
		markDoneHook = func(ctx context.Context, target, artifactName string, input []byte) error {
			return repo.MarkDuplicate(ctx, target, artifactName, input, 8*time.Hour)
		}
	}

	return persistHook, dedupHook, markDoneHook
}

func wireGogoStreaming(runtimeApp *app.App) {
	repo := runtimeApp.Repo
	reg := runtimeApp.Registry
	a, err := reg.Get("gogo")
	if err != nil {
		return
	}
	a.(*artifact.GogoArtifact).SetResultHandler(func(ctx context.Context, target string, result *sdktypes.GOGOResult) {
		raw, _ := json.Marshal(result)
		_ = repo.SaveRawEvent(ctx, &data.RawEvent{
			ID:         fmt.Sprintf("gogo-stream-%d", time.Now().UnixNano()),
			Artifact:   "gogo",
			TargetID:   target,
			TargetType: targetType(target),
			WorkflowID: "",
			Data:       raw,
		})
		wrapped, _ := json.Marshal(map[string]interface{}{"results": []json.RawMessage{raw}})
		if err := runtimeApp.Pipelines.Gogo.Process(ctx, target, wrapped); err != nil {
			log.Printf("WARNING: gogo streaming ETL failed: %v", err)
		}
	})
}

func registerArtifactActivities(w sdkworker.Worker, runtimeApp *app.App, persistHook artifact.PersistHook, dedupHook artifact.DedupHook, markDoneHook artifact.MarkDoneHook, onlyArtifact string) {
	repo := runtimeApp.Repo
	reg := runtimeApp.Registry
	rawEvent := buildRawEventHandler(runtimeApp)
	statsHook := buildStatsHook(repo)
	for _, info := range reg.List() {
		if onlyArtifact != "" && info.Name != onlyArtifact {
			continue
		}
		a, _ := reg.Get(info.Name)
		w.RegisterActivityWithOptions(
			artifact.NewActivityFunc(a, persistHook, dedupHook, markDoneHook, rawEvent, statsHook),
			activity.RegisterOptions{Name: info.Name},
		)
		log.Printf("registered activity: %s", info.Name)
	}
}

func buildRawEventHandler(runtimeApp *app.App) artifact.RawEventHandler {
	repo := runtimeApp.Repo
	return func(ctx context.Context, artifactName, target, workflowID, campaignID string, eventData []byte) {
		if err := repo.SaveRawEvent(ctx, &data.RawEvent{
			ID:         fmt.Sprintf("%s-%d", workflowID, time.Now().UnixNano()),
			CampaignID: campaignID,
			Artifact:   artifactName,
			TargetID:   target,
			TargetType: targetType(target),
			WorkflowID: workflowID,
			Data:       eventData,
		}); err != nil {
			log.Printf("WARNING: raw event save failed for %s: %v", artifactName, err)
		}
		processETL(runtimeApp, ctx, artifactName, target, campaignID, eventData)
	}
}

func buildStatsHook(repo *data.Repository) artifact.StatsHook {
	return func(ctx context.Context, artifactName, target, workflowID, campaignID string, stats []artifact.ExecutionStat) error {
		for i, stat := range stats {
			if err := repo.SaveArtifactStat(ctx, data.ArtifactStat{
				ID:         fmt.Sprintf("%s-%s-%d-%d", workflowID, artifactName, time.Now().UnixNano(), i),
				CampaignID: campaignID,
				WorkflowID: workflowID,
				Artifact:   artifactName,
				Target:     target,
				Engine:     stat.Engine,
				Task:       stat.Task,
				Targets:    stat.Targets,
				Tasks:      stat.Tasks,
				Requests:   stat.Requests,
				Results:    stat.Results,
				Errors:     stat.Errors,
				DurationMs: stat.DurationMs,
			}); err != nil {
				return err
			}
		}
		return nil
	}
}

func processETL(runtimeApp *app.App, ctx context.Context, artifactName, target, campaignID string, eventData []byte) {
	ctx = etl.WithCampaignID(ctx, campaignID)
	var etlErr error
	switch artifactName {
	case "gogo":
		etlErr = runtimeApp.Pipelines.Gogo.Process(ctx, target, eventData)
	case "fingers":
		etlErr = runtimeApp.Pipelines.Fingers.Process(ctx, target, eventData)
	case "neutron":
		etlErr = runtimeApp.Pipelines.Neutron.Process(ctx, target, eventData)
	case "spray":
		etlErr = runtimeApp.Pipelines.Spray.Process(ctx, target, eventData)
	case "zombie":
		etlErr = runtimeApp.Pipelines.Zombie.Process(ctx, target, eventData)
	case "cdncheck":
		etlErr = runtimeApp.Pipelines.Cdncheck.Process(ctx, target, eventData)
	case "dnsx":
		etlErr = runtimeApp.Pipelines.DNSX.Process(ctx, target, eventData)
	case "nuclei":
		etlErr = runtimeApp.Pipelines.Nuclei.Process(ctx, target, eventData)
	}
	if etlErr != nil {
		log.Printf("WARNING: ETL failed for %s: %v", artifactName, etlErr)
	}
}

func registerPlannerActivities(w sdkworker.Worker, repo *data.Repository) {
	planActivity := planner.NewActivity(repo)
	w.RegisterActivityWithOptions(planActivity.PlanTarget, activity.RegisterOptions{Name: planner.PlanTargetActivityName})
	w.RegisterActivityWithOptions(planActivity.PlanDAGTarget, activity.RegisterOptions{Name: planner.PlanDAGTargetActivityName})
	w.RegisterActivityWithOptions(planActivity.ClaimAction, activity.RegisterOptions{Name: planner.ClaimActionActivityName})
	w.RegisterActivityWithOptions(planActivity.CompleteAction, activity.RegisterOptions{Name: planner.CompleteActionActivityName})
	w.RegisterActivityWithOptions(planActivity.EvaluateCondition, activity.RegisterOptions{Name: planner.EvaluateConditionActivityName})
	w.RegisterActivityWithOptions(planActivity.UpsertBatchRun, activity.RegisterOptions{Name: planner.UpsertBatchRunActivityName})
	w.RegisterActivityWithOptions(planActivity.UpsertBatchChunk, activity.RegisterOptions{Name: planner.UpsertBatchChunkActivityName})
	w.RegisterActivityWithOptions(planActivity.UpsertWorkItem, activity.RegisterOptions{Name: planner.UpsertWorkItemActivityName})
	w.RegisterActivityWithOptions(planActivity.ClaimWorkItem, activity.RegisterOptions{Name: planner.ClaimWorkItemActivityName})
	w.RegisterActivityWithOptions(planActivity.SetWorkItemStatus, activity.RegisterOptions{Name: planner.SetWorkItemStatusActivityName})
	w.RegisterActivityWithOptions(planActivity.HeartbeatWorkItem, activity.RegisterOptions{Name: planner.HeartbeatWorkItemActivityName})
	w.RegisterActivityWithOptions(planActivity.GetCampaignStatus, activity.RegisterOptions{Name: planner.GetCampaignStatusActivityName})
	w.RegisterActivityWithOptions(planActivity.WorkItemSummary, activity.RegisterOptions{Name: planner.WorkItemSummaryActivityName})
	w.RegisterActivityWithOptions(planActivity.RecoverStaleWorkItems, activity.RegisterOptions{Name: planner.RecoverStaleWorkItemsActivityName})
	w.RegisterActivityWithOptions(planActivity.RequeueRetryWaitingWorkItems, activity.RegisterOptions{Name: planner.RequeueRetryWaitingWorkItemsActivityName})
	log.Printf("registered activity: %s", planner.PlanTargetActivityName)
	log.Printf("registered activity: %s", planner.PlanDAGTargetActivityName)
	log.Printf("registered activity: %s", planner.ClaimActionActivityName)
	log.Printf("registered activity: %s", planner.CompleteActionActivityName)
	log.Printf("registered activity: %s", planner.EvaluateConditionActivityName)
	log.Printf("registered activity: %s", planner.UpsertBatchRunActivityName)
	log.Printf("registered activity: %s", planner.UpsertBatchChunkActivityName)
	log.Printf("registered activity: %s", planner.UpsertWorkItemActivityName)
	log.Printf("registered activity: %s", planner.ClaimWorkItemActivityName)
	log.Printf("registered activity: %s", planner.SetWorkItemStatusActivityName)
	log.Printf("registered activity: %s", planner.HeartbeatWorkItemActivityName)
	log.Printf("registered activity: %s", planner.GetCampaignStatusActivityName)
	log.Printf("registered activity: %s", planner.WorkItemSummaryActivityName)
	log.Printf("registered activity: %s", planner.RecoverStaleWorkItemsActivityName)
	log.Printf("registered activity: %s", planner.RequeueRetryWaitingWorkItemsActivityName)
}

func registerWorkflows(w sdkworker.Worker) {
	w.RegisterWorkflow(workflow.DomainWorkflow)
	w.RegisterWorkflow(workflow.IPWorkflow)
	w.RegisterWorkflow(workflow.CompanyWorkflow)
	w.RegisterWorkflow(workflow.PortScanWorkflow)
	w.RegisterWorkflow(workflow.BatchPortScanWorkflow)
	w.RegisterWorkflow(workflow.SchedulerWorkflow)
	w.RegisterWorkflow(workflow.DAGWorkflow)
	w.RegisterWorkflow(workflow.PlannedDAGWorkflow)
	w.RegisterWorkflow(workflow.ActionWorkflow)
	w.RegisterWorkflow(workflow.PlannedWorkflow)
	log.Println("registered workflows: domain, ip, company, portscan, batch_portscan, scheduler, dag, planned_dag, action, planned")
}

func targetType(raw string) string {
	return data.TargetType(raw)
}
