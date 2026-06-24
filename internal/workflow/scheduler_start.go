package workflow

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/data"
	enumspb "go.temporal.io/api/enums/v1"
	sdkclient "go.temporal.io/sdk/client"
)

type SchedulerStartOptions struct {
	WorkflowID               string
	WorkflowIDReusePolicy    enumspb.WorkflowIdReusePolicy
	WorkflowIDConflictPolicy enumspb.WorkflowIdConflictPolicy
	TaskQueue                string
	RunPlannedDAG            bool
	MaxAttempts              int
	RetryDelaySeconds        int
	ActivityTimeoutSeconds   int
	CampaignPhase            string
	PlannedDAGMaxIterations  int
	SprayShardBaseURLs       int
	SprayShardWords          int
	NucleiGroupTargets       int
	NucleiGroupTemplates     int
	ContinueAfter            int
	MaxContinueRuns          int
}

func StartSchedulerForBatchRun(ctx context.Context, temporalClient sdkclient.Client, run data.BatchRun, opts SchedulerStartOptions) (sdkclient.WorkflowRun, error) {
	if temporalClient == nil {
		return nil, fmt.Errorf("temporal client is required")
	}
	ports := strings.TrimSpace(run.Ports)
	if ports == "" {
		return nil, fmt.Errorf("batch run has no ports")
	}
	workflowID := opts.WorkflowID
	if workflowID == "" {
		workflowID = fmt.Sprintf("batch_scheduler_resume-%s-%d", run.ID, time.Now().UnixNano())
	}
	startOptions := sdkclient.StartWorkflowOptions{
		ID:                  workflowID,
		TaskQueue:           opts.TaskQueue,
		WorkflowTaskTimeout: ControlWorkflowTaskTimeout,
	}
	if opts.WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_UNSPECIFIED {
		startOptions.WorkflowIDReusePolicy = opts.WorkflowIDReusePolicy
	}
	if opts.WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_UNSPECIFIED {
		startOptions.WorkflowIDConflictPolicy = opts.WorkflowIDConflictPolicy
	}
	return temporalClient.ExecuteWorkflow(ctx, startOptions, SchedulerWorkflow, SchedulerWorkflowInput{
		BatchID: run.ID,
		BatchInput: BatchPortScanInput{
			Targets:                 data.SplitList(run.Target, true),
			CampaignID:              run.CampaignID,
			Ports:                   ports,
			MaxAttempts:             opts.MaxAttempts,
			RetryDelaySeconds:       opts.RetryDelaySeconds,
			ActivityTimeoutSeconds:  opts.ActivityTimeoutSeconds,
			CampaignPhase:           opts.CampaignPhase,
			RunPlannedDAG:           opts.RunPlannedDAG,
			PlannedDAGMaxIterations: opts.PlannedDAGMaxIterations,
			SprayShardBaseURLs:      opts.SprayShardBaseURLs,
			SprayShardWords:         opts.SprayShardWords,
			NucleiGroupTargets:      opts.NucleiGroupTargets,
			NucleiGroupTemplates:    opts.NucleiGroupTemplates,
		},
		TotalChunks:     run.TotalChunks,
		ContinueAfter:   opts.ContinueAfter,
		MaxContinueRuns: opts.MaxContinueRuns,
	})
}
