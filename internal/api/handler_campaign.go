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
	Phase       string   `json:"phase,omitempty"`
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
	if req.Phase == "" {
		req.Phase = data.CampaignPhaseBootstrap
	}
	campaign := data.Campaign{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Status:      req.Status,
		Phase:       req.Phase,
		PhaseReason: "campaign created",
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
	events, _ := s.repo.GetCampaignPhaseEvents(c.Request.Context(), campaign.ID, 20, 0)
	c.JSON(http.StatusOK, gin.H{
		"campaign":     campaign,
		"phase_events": events,
	})
}

func (s *Server) GetCampaignRuntime(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	view, err := s.repo.GetCampaignRuntimeViewWithCapacity(c.Request.Context(), c.Param("id"), c.Query("batch_id"), s.sdkCapacityOverrides())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, view)
}

func (s *Server) sdkCapacityOverrides() map[string]int {
	if s == nil || s.cfg == nil {
		return nil
	}
	overrides := map[string]int{}
	if s.cfg.Artifacts.Gogo.Capacity > 0 {
		overrides["gogo"] = s.cfg.Artifacts.Gogo.Capacity
	}
	if s.cfg.Artifacts.Spray.Capacity > 0 {
		overrides["spray"] = s.cfg.Artifacts.Spray.Capacity
	}
	if s.cfg.Artifacts.Neutron.Capacity > 0 {
		overrides["neutron"] = s.cfg.Artifacts.Neutron.Capacity
	}
	if s.cfg.Artifacts.Zombie.Capacity > 0 {
		overrides["zombie"] = s.cfg.Artifacts.Zombie.Capacity
	}
	if s.cfg.Artifacts.Proton.Capacity > 0 {
		overrides["proton"] = s.cfg.Artifacts.Proton.Capacity
	}
	if len(overrides) == 0 {
		return nil
	}
	return overrides
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
