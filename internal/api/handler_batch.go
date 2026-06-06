package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	c.JSON(http.StatusOK, gin.H{
		"batches": runs,
		"total":   len(runs),
		"limit":   limit,
		"offset":  offset,
	})
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
		ports = "top1000"
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
