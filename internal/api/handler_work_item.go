package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/gin-gonic/gin"
)

type WorkItemRetryAPIRequest struct {
	ID            string              `json:"id,omitempty"`
	CampaignID    string              `json:"campaign_id,omitempty"`
	BatchID       string              `json:"batch_id,omitempty"`
	Status        string              `json:"status,omitempty"`
	Type          string              `json:"type,omitempty"`
	Artifact      string              `json:"artifact,omitempty"`
	Target        string              `json:"target,omitempty"`
	FromStatuses  []string            `json:"from_statuses,omitempty"`
	ResetAttempts bool                `json:"reset_attempts,omitempty"`
	Filter        data.WorkItemFilter `json:"filter,omitempty"`
}

type WorkItemFilterAPIRequest struct {
	ID         string              `json:"id,omitempty"`
	CampaignID string              `json:"campaign_id,omitempty"`
	BatchID    string              `json:"batch_id,omitempty"`
	Status     string              `json:"status,omitempty"`
	Type       string              `json:"type,omitempty"`
	Artifact   string              `json:"artifact,omitempty"`
	Target     string              `json:"target,omitempty"`
	Limit      int                 `json:"limit,omitempty"`
	Filter     data.WorkItemFilter `json:"filter,omitempty"`
}

type WorkItemResponse struct {
	ID             string          `json:"id"`
	CampaignID     string          `json:"campaign_id,omitempty"`
	BatchID        string          `json:"batch_id,omitempty"`
	ParentID       string          `json:"parent_id,omitempty"`
	Type           string          `json:"type"`
	Target         string          `json:"target"`
	Artifact       string          `json:"artifact"`
	Queue          string          `json:"queue,omitempty"`
	Input          json.RawMessage `json:"input,omitempty"`
	Status         string          `json:"status"`
	Attempts       int             `json:"attempts"`
	MaxAttempts    int             `json:"max_attempts"`
	WorkflowID     string          `json:"workflow_id,omitempty"`
	Error          string          `json:"error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	HeartbeatAt    time.Time       `json:"heartbeat_at,omitempty"`
	LeaseExpiresAt time.Time       `json:"lease_expires_at,omitempty"`
	StartedAt      time.Time       `json:"started_at,omitempty"`
	CompletedAt    time.Time       `json:"completed_at,omitempty"`
	Tail           bool            `json:"tail"`
	TailAt         *time.Time      `json:"tail_at,omitempty"`
	TailReason     string          `json:"tail_reason,omitempty"`
	IsStale        bool            `json:"is_stale,omitempty"`
	HeartbeatStale bool            `json:"heartbeat_stale,omitempty"`
	RunningSeconds int64           `json:"running_seconds,omitempty"`
	HeartbeatAge   int64           `json:"heartbeat_age_seconds,omitempty"`
	LeaseRemaining int64           `json:"lease_remaining_seconds,omitempty"`
}

func (s *Server) ListWorkItems(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	if offset < 0 {
		offset = 0
	}
	rawInput := c.Query("raw_input") == "true"

	items, err := s.repo.GetWorkItems(
		c.Request.Context(),
		c.Query("campaign_id"),
		c.Query("batch_id"),
		c.Query("status"),
		c.Query("type"),
		c.Query("artifact"),
		c.Query("target"),
		limit,
		offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out := make([]WorkItemResponse, 0, len(items))
	for _, item := range items {
		out = append(out, workItemResponse(item, rawInput))
	}
	c.JSON(http.StatusOK, gin.H{
		"work_items": out,
		"total":      len(items),
		"limit":      limit,
		"offset":     offset,
	})
}

func workItemResponse(item data.WorkItem, rawInput bool) WorkItemResponse {
	now := time.Now()
	resp := WorkItemResponse{
		ID:             item.ID,
		CampaignID:     item.CampaignID,
		BatchID:        item.BatchID,
		ParentID:       item.ParentID,
		Type:           item.Type,
		Target:         item.Target,
		Artifact:       item.Artifact,
		Queue:          item.Queue,
		Input:          inputJSONResponse(item.Input, rawInput),
		Status:         item.Status,
		Attempts:       item.Attempts,
		MaxAttempts:    item.MaxAttempts,
		WorkflowID:     item.WorkflowID,
		Error:          item.Error,
		CreatedAt:      item.CreatedAt,
		UpdatedAt:      item.UpdatedAt,
		HeartbeatAt:    item.HeartbeatAt,
		LeaseExpiresAt: item.LeaseExpiresAt,
		StartedAt:      item.StartedAt,
		CompletedAt:    item.CompletedAt,
		Tail:           item.Tail,
		TailReason:     item.TailReason,
	}
	if item.Tail && !item.TailAt.IsZero() {
		resp.TailAt = &item.TailAt
	}
	if item.Status == data.WorkItemStatusStarting || item.Status == data.WorkItemStatusRunning {
		if !item.StartedAt.IsZero() {
			resp.RunningSeconds = int64(now.Sub(item.StartedAt).Seconds())
		}
		if !item.HeartbeatAt.IsZero() {
			resp.HeartbeatAge = int64(now.Sub(item.HeartbeatAt).Seconds())
			resp.HeartbeatStale = resp.HeartbeatAge > int64((10 * time.Minute).Seconds())
		}
		if !item.LeaseExpiresAt.IsZero() {
			resp.LeaseRemaining = int64(item.LeaseExpiresAt.Sub(now).Seconds())
			resp.IsStale = item.LeaseExpiresAt.Before(now)
		}
	}
	return resp
}

func (s *Server) WorkItemSummary(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	filter := data.WorkItemFilter{
		CampaignID: c.Query("campaign_id"),
		BatchID:    c.Query("batch_id"),
		Status:     c.Query("status"),
		Type:       c.Query("type"),
		Artifact:   c.Query("artifact"),
		Target:     c.Query("target"),
	}
	summary, err := s.repo.GetWorkItemProgressSummary(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	artifactStats, err := s.repo.GetArtifactStatSummary(
		c.Request.Context(),
		c.Query("campaign_id"),
		"",
		c.Query("artifact"),
		c.Query("target"),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var campaign *data.Campaign
	var runtimeView *data.CampaignRuntimeView
	if filter.CampaignID != "" {
		campaign, _ = s.repo.GetCampaign(c.Request.Context(), filter.CampaignID)
		if view, viewErr := s.repo.GetCampaignRuntimeView(c.Request.Context(), filter.CampaignID, filter.BatchID); viewErr == nil {
			runtimeView = &view
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"by_status":          summary.ByStatus,
		"campaign":           campaign,
		"runtime":            runtimeView,
		"total":              summary.Total,
		"overall":            summary.Overall,
		"by_type":            summary.ByType,
		"by_queue":           summary.ByQueue,
		"by_artifact":        summary.ByArtifact,
		"by_target":          summary.ByTarget,
		"eta_seconds":        summary.ETASeconds,
		"throughput_per_min": summary.ThroughputPerMin,
		"artifact_stats":     artifactStats,
		"generated_at":       summary.GeneratedAt,
	})
}

func (s *Server) RetryWorkItems(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req WorkItemRetryAPIRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}
	filter := mergeWorkItemRetryFilter(req)
	result, err := s.repo.RetryWorkItems(c.Request.Context(), data.WorkItemRetryRequest{
		Filter:        filter,
		FromStatuses:  req.FromStatuses,
		ResetAttempts: req.ResetAttempts,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) ResumeWorkItems(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req WorkItemFilterAPIRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}
	result, err := s.repo.ResumeWorkItems(c.Request.Context(), mergeWorkItemFilter(req))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) PauseWorkItems(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req WorkItemFilterAPIRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}
	result, err := s.repo.PauseWorkItems(c.Request.Context(), mergeWorkItemFilter(req))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) RecoverStaleWorkItems(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req WorkItemFilterAPIRequest
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
	}
	result, err := s.repo.RecoverStaleWorkItems(c.Request.Context(), mergeWorkItemFilter(req), req.Limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func mergeWorkItemRetryFilter(req WorkItemRetryAPIRequest) data.WorkItemFilter {
	filter := req.Filter
	if req.ID != "" {
		filter.ID = req.ID
	}
	if req.CampaignID != "" {
		filter.CampaignID = req.CampaignID
	}
	if req.BatchID != "" {
		filter.BatchID = req.BatchID
	}
	if req.Status != "" {
		filter.Status = req.Status
	}
	if req.Type != "" {
		filter.Type = req.Type
	}
	if req.Artifact != "" {
		filter.Artifact = req.Artifact
	}
	if req.Target != "" {
		filter.Target = req.Target
	}
	return filter
}

func mergeWorkItemFilter(req WorkItemFilterAPIRequest) data.WorkItemFilter {
	filter := req.Filter
	if req.ID != "" {
		filter.ID = req.ID
	}
	if req.CampaignID != "" {
		filter.CampaignID = req.CampaignID
	}
	if req.BatchID != "" {
		filter.BatchID = req.BatchID
	}
	if req.Status != "" {
		filter.Status = req.Status
	}
	if req.Type != "" {
		filter.Type = req.Type
	}
	if req.Artifact != "" {
		filter.Artifact = req.Artifact
	}
	if req.Target != "" {
		filter.Target = req.Target
	}
	return filter
}
