package api

import (
	"net/http"
	"strconv"

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

	c.JSON(http.StatusOK, gin.H{
		"work_items": items,
		"total":      len(items),
		"limit":      limit,
		"offset":     offset,
	})
}

func (s *Server) WorkItemSummary(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	counts, err := s.repo.CountWorkItemsByStatus(
		c.Request.Context(),
		c.Query("campaign_id"),
		c.Query("batch_id"),
		c.Query("type"),
		c.Query("artifact"),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total := 0
	for _, count := range counts {
		total += count
	}
	c.JSON(http.StatusOK, gin.H{
		"by_status": counts,
		"total":     total,
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
