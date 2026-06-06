package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/0xrawptr/weave/internal/workflow"
	"github.com/gin-gonic/gin"
	"go.temporal.io/sdk/client"
)

type StartActionRequest struct {
	Artifact               string                 `json:"artifact"`
	Target                 string                 `json:"target"`
	CampaignID             string                 `json:"campaign_id,omitempty"`
	Input                  map[string]interface{} `json:"input"`
	ActivityTimeoutSeconds int                    `json:"activity_timeout_seconds,omitempty"`
}

type ActionRecordResponse struct {
	ID          string          `json:"id"`
	CampaignID  string          `json:"campaign_id,omitempty"`
	Target      string          `json:"target"`
	Artifact    string          `json:"artifact"`
	Input       json.RawMessage `json:"input"`
	Priority    int             `json:"priority"`
	Reason      string          `json:"reason"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	WorkflowID  string          `json:"workflow_id"`
	Error       string          `json:"error,omitempty"`
	CreatedAt   interface{}     `json:"created_at"`
	UpdatedAt   interface{}     `json:"updated_at"`
	StartedAt   interface{}     `json:"started_at,omitempty"`
	CompletedAt interface{}     `json:"completed_at,omitempty"`
}

func (s *Server) ListActions(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	records, err := s.repo.GetActionRecordsFiltered(c.Request.Context(), c.Query("target"), c.Query("campaign_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]ActionRecordResponse, 0, len(records))
	for _, record := range records {
		out = append(out, ActionRecordResponse{
			ID:          record.ID,
			CampaignID:  record.CampaignID,
			Target:      record.Target,
			Artifact:    record.Artifact,
			Input:       json.RawMessage(record.Input),
			Priority:    record.Priority,
			Reason:      record.Reason,
			Status:      record.Status,
			Attempts:    record.Attempts,
			WorkflowID:  record.WorkflowID,
			Error:       record.Error,
			CreatedAt:   record.CreatedAt,
			UpdatedAt:   record.UpdatedAt,
			StartedAt:   record.StartedAt,
			CompletedAt: record.CompletedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"actions": out, "total": len(out)})
}

// StartAction executes a single artifact action through Temporal.
func (s *Server) StartAction(c *gin.Context) {
	var req StartActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Artifact == "" || req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artifact and target are required"})
		return
	}
	if s.temporal == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporal service not available"})
		return
	}
	if _, err := s.registry.Get(req.Artifact); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	workflowID := generateWorkflowID("action-" + req.Artifact)
	run, err := s.temporal.ExecuteWorkflow(context.Background(), client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: s.cfg.Temporal.TaskQueue,
	}, workflow.ActionWorkflow, workflow.ActionWorkflowInput{
		Artifact:               req.Artifact,
		Target:                 req.Target,
		CampaignID:             req.CampaignID,
		Input:                  req.Input,
		ActivityTimeoutSeconds: req.ActivityTimeoutSeconds,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"workflow_id": run.GetID(),
		"run_id":      run.GetRunID(),
		"artifact":    req.Artifact,
		"target":      req.Target,
		"campaign_id": req.CampaignID,
	})
}
