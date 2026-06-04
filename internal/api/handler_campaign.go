package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/gin-gonic/gin"
)

type CreateCampaignRequest struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Status      string   `json:"status,omitempty"`
	Targets     []string `json:"targets,omitempty"`
}

type UpdateCampaignStatusRequest struct {
	Status string `json:"status"`
}

func (s *Server) CreateCampaign(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req CreateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.ID == "" {
		req.ID = data.GenerateID("campaign", req.Name)
	}
	if req.Status == "" {
		req.Status = data.CampaignStatusActive
	}
	campaign := data.Campaign{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Status:      req.Status,
		Targets:     cleanStringSlice(req.Targets),
	}
	if err := s.repo.UpsertCampaign(c.Request.Context(), campaign); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created, err := s.repo.GetCampaign(c.Request.Context(), campaign.ID)
	if err != nil {
		c.JSON(http.StatusCreated, campaign)
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (s *Server) ListCampaigns(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	campaigns, err := s.repo.GetCampaigns(c.Request.Context(), c.Query("status"), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"campaigns": campaigns,
		"total":     len(campaigns),
		"limit":     limit,
		"offset":    offset,
	})
}

func (s *Server) GetCampaign(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	campaign, err := s.repo.GetCampaign(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, campaign)
}

func (s *Server) UpdateCampaignStatus(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	var req UpdateCampaignStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.repo.UpdateCampaignStatus(c.Request.Context(), c.Param("id"), req.Status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	campaign, err := s.repo.GetCampaign(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": req.Status})
		return
	}
	c.JSON(http.StatusOK, campaign)
}
