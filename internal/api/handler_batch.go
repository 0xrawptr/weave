package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/workflow"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

type RetryFailedBatchChunksRequest struct {
	MaxConcurrency          int                     `json:"max_concurrency,omitempty"`
	MaxAttempts             int                     `json:"max_attempts,omitempty"`
	RetryDelaySeconds       int                     `json:"retry_delay_seconds,omitempty"`
	PriorityTargets         []string                `json:"priority_targets,omitempty"`
	ActivityTimeoutSeconds  int                     `json:"activity_timeout_seconds,omitempty"`
	QueueLimits             map[string]int          `json:"queue_limits,omitempty"`
	ResourceLimits          workflow.ResourceLimits `json:"resource_limits,omitempty"`
	RunPlannedDAG           bool                    `json:"run_planned_dag,omitempty"`
	PlannedDAGConcurrency   int                     `json:"planned_dag_concurrency,omitempty"`
	PlannedDAGMaxIterations int                     `json:"planned_dag_max_iterations,omitempty"`
	PlannedDAGContinue      bool                    `json:"planned_dag_continue_on_failure,omitempty"`
	SprayShardBaseURLs      int                     `json:"spray_shard_base_urls,omitempty"`
	SprayShardWords         int                     `json:"spray_shard_words,omitempty"`
	NucleiGroupTargets      int                     `json:"nuclei_group_targets,omitempty"`
	NucleiGroupTemplates    int                     `json:"nuclei_group_templates,omitempty"`
}

type ResumeBatchSchedulerRequest struct {
	MaxConcurrency          int                     `json:"max_concurrency,omitempty"`
	MaxAttempts             int                     `json:"max_attempts,omitempty"`
	RetryDelaySeconds       int                     `json:"retry_delay_seconds,omitempty"`
	ActivityTimeoutSeconds  int                     `json:"activity_timeout_seconds,omitempty"`
	QueueLimits             map[string]int          `json:"queue_limits,omitempty"`
	ResourceLimits          workflow.ResourceLimits `json:"resource_limits,omitempty"`
	RunPlannedDAG           *bool                   `json:"run_planned_dag,omitempty"`
	PlannedDAGConcurrency   int                     `json:"planned_dag_concurrency,omitempty"`
	PlannedDAGMaxIterations int                     `json:"planned_dag_max_iterations,omitempty"`
	PlannedDAGContinue      bool                    `json:"planned_dag_continue_on_failure,omitempty"`
	SprayShardBaseURLs      int                     `json:"spray_shard_base_urls,omitempty"`
	SprayShardWords         int                     `json:"spray_shard_words,omitempty"`
	NucleiGroupTargets      int                     `json:"nuclei_group_targets,omitempty"`
	NucleiGroupTemplates    int                     `json:"nuclei_group_templates,omitempty"`
	ContinueAfter           int                     `json:"continue_after,omitempty"`
	IdleWaitSeconds         int                     `json:"idle_wait_seconds,omitempty"`
	MaxContinueRuns         int                     `json:"max_continue_runs,omitempty"`
}

func (s *Server) ListBatches(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	status := c.Query("status")
	campaignID := c.Query("campaign_id")

	runs, err := s.repo.GetBatchRunsFiltered(c.Request.Context(), status, campaignID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.enrichBatchRunsWithLiveProgress(c.Request.Context(), runs)
	c.JSON(http.StatusOK, gin.H{
		"batches": runs,
		"total":   len(runs),
		"limit":   limit,
		"offset":  offset,
	})
}

func (s *Server) enrichBatchRunsWithLiveProgress(ctx context.Context, runs []data.BatchRun) {
	if s == nil || s.repo == nil {
		return
	}
	for i := range runs {
		counts, err := s.repo.CountWorkItemsByStatus(ctx, runs[i].CampaignID, runs[i].ID, "portscan_chunk", "gogo")
		if err != nil || len(counts) == 0 {
			continue
		}
		completed := counts[data.WorkItemStatusCompleted]
		failed := counts[data.WorkItemStatusFailed] + counts[data.WorkItemStatusDead]
		running := counts[data.WorkItemStatusRunning]
		pending := counts[data.WorkItemStatusPending] + counts[data.WorkItemStatusRetryWaiting] + counts[data.WorkItemStatusPaused]
		cancelled := counts[data.WorkItemStatusCancelled]
		skipped := counts[data.WorkItemStatusSkipped]

		runs[i].Completed = completed
		runs[i].Failed = failed
		done := completed + failed + cancelled + skipped
		active := running + pending
		switch {
		case active > 0:
			runs[i].Status = "running"
		case failed > 0 && completed > 0:
			runs[i].Status = "partial"
		case failed > 0 && completed == 0:
			runs[i].Status = "failed"
		case runs[i].TotalChunks > 0 && done >= runs[i].TotalChunks:
			runs[i].Status = "completed"
		}
	}
}

func (s *Server) ListBatchChunks(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	status := c.Query("status")
	batchID := c.Param("id")

	chunks, err := s.repo.GetBatchChunks(c.Request.Context(), batchID, status, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"batch_id": batchID,
		"chunks":   chunks,
		"total":    len(chunks),
		"limit":    limit,
		"offset":   offset,
	})
}

func (s *Server) RetryFailedBatchChunks(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}

	var req RetryFailedBatchChunksRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}

	batchID := c.Param("id")
	run, err := s.repo.GetBatchRun(c.Request.Context(), batchID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	chunks, err := s.repo.GetFailedBatchChunks(c.Request.Context(), batchID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(chunks) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"batch_id": batchID,
			"message":  "no failed chunks to retry",
			"count":    0,
		})
		return
	}

	targets := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		targets = append(targets, chunk.Chunk)
	}
	ports := run.Ports
	if ports == "" {
		ports = "top3"
	}
	workflowID := fmt.Sprintf("batch_retry-%s-%d", batchID, time.Now().UnixNano())
	wfRun, err := s.temporal.ExecuteWorkflow(context.Background(), client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: s.cfg.Temporal.TaskQueue,
	}, workflow.BatchPortScanWorkflow, workflow.BatchPortScanInput{
		Targets:                 targets,
		PriorityTargets:         req.PriorityTargets,
		CampaignID:              run.CampaignID,
		Ports:                   ports,
		MaxConcurrency:          req.MaxConcurrency,
		MaxAttempts:             req.MaxAttempts,
		RetryDelaySeconds:       req.RetryDelaySeconds,
		ActivityTimeoutSeconds:  req.ActivityTimeoutSeconds,
		QueueLimits:             req.QueueLimits,
		ResourceLimits:          req.ResourceLimits,
		RunPlannedDAG:           req.RunPlannedDAG,
		PlannedDAGConcurrency:   req.PlannedDAGConcurrency,
		PlannedDAGMaxIterations: req.PlannedDAGMaxIterations,
		PlannedDAGContinue:      req.PlannedDAGContinue,
		SprayShardBaseURLs:      req.SprayShardBaseURLs,
		SprayShardWords:         req.SprayShardWords,
		NucleiGroupTargets:      req.NucleiGroupTargets,
		NucleiGroupTemplates:    req.NucleiGroupTemplates,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"batch_id":          batchID,
		"retry_workflow_id": wfRun.GetID(),
		"run_id":            wfRun.GetRunID(),
		"targets":           targets,
		"count":             len(targets),
	})
}

func (s *Server) ResumeBatchScheduler(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}

	var req ResumeBatchSchedulerRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}

	batchID := c.Param("id")
	run, err := s.repo.GetBatchRun(c.Request.Context(), batchID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	runPlannedDAG := true
	if req.RunPlannedDAG != nil {
		runPlannedDAG = *req.RunPlannedDAG
	}
	ports := run.Ports
	if ports == "" {
		ports = "top3"
	}
	workflowID := fmt.Sprintf("batch_scheduler_resume-%s-%d", batchID, time.Now().UnixNano())
	wfRun, err := s.temporal.ExecuteWorkflow(context.Background(), client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: s.cfg.Temporal.TaskQueue,
	}, workflow.SchedulerWorkflow, workflow.SchedulerWorkflowInput{
		BatchID: batchID,
		BatchInput: workflow.BatchPortScanInput{
			Targets:                 splitBatchRunTargets(run.Target),
			CampaignID:              run.CampaignID,
			Ports:                   ports,
			MaxConcurrency:          req.MaxConcurrency,
			MaxAttempts:             req.MaxAttempts,
			RetryDelaySeconds:       req.RetryDelaySeconds,
			ActivityTimeoutSeconds:  req.ActivityTimeoutSeconds,
			QueueLimits:             req.QueueLimits,
			ResourceLimits:          req.ResourceLimits,
			RunPlannedDAG:           runPlannedDAG,
			PlannedDAGConcurrency:   req.PlannedDAGConcurrency,
			PlannedDAGMaxIterations: req.PlannedDAGMaxIterations,
			PlannedDAGContinue:      req.PlannedDAGContinue,
			SprayShardBaseURLs:      req.SprayShardBaseURLs,
			SprayShardWords:         req.SprayShardWords,
			NucleiGroupTargets:      req.NucleiGroupTargets,
			NucleiGroupTemplates:    req.NucleiGroupTemplates,
		},
		TotalChunks:     run.TotalChunks,
		ContinueAfter:   req.ContinueAfter,
		IdleWaitSeconds: req.IdleWaitSeconds,
		MaxContinueRuns: req.MaxContinueRuns,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"batch_id":             batchID,
		"scheduler_workflow":   wfRun.GetID(),
		"run_id":               wfRun.GetRunID(),
		"run_planned_dag":      runPlannedDAG,
		"pending_work_items":   fmt.Sprintf("/api/v1/work-items?batch_id=%s&status=pending", batchID),
		"summary":              fmt.Sprintf("/api/v1/work-items/summary?batch_id=%s", batchID),
		"original_workflow_id": run.WorkflowID,
	})
}

func splitBatchRunTargets(target string) []string {
	if strings.TrimSpace(target) == "" {
		return nil
	}
	return strings.FieldsFunc(target, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}
