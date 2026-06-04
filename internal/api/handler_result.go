package api

import (
	"net/http"
	"strconv"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/gin-gonic/gin"
)

type UpdateResultStatusRequest struct {
	Status string `json:"status"`
}

// ListResults returns a paginated list of results from the data store.
func (s *Server) ListResults(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	targetID := c.Query("target_id")
	assetType := c.Query("type")
	status := c.Query("status")
	campaignID := c.Query("campaign_id")

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	assets, err := s.repo.Postgres.QueryAssetsFiltered(c.Request.Context(), targetID, assetType, campaignID, status, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, _ := s.repo.Postgres.CountAssetsFilteredByCampaign(c.Request.Context(), targetID, assetType, "", status, campaignID)
	c.JSON(http.StatusOK, gin.H{
		"results": assets,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// QueryGraph queries the Neo4j graph for related assets.
func (s *Server) QueryGraph(c *gin.Context) {
	assetID := c.Query("asset_id")
	if assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_id query parameter is required"})
		return
	}

	depth := 3
	if d, err := strconv.Atoi(c.DefaultQuery("depth", "3")); err == nil && d > 0 && d <= 10 {
		depth = d
	}

	if s.repo == nil || s.repo.Neo4j == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "graph store not available"})
		return
	}

	nodes, err := s.repo.Neo4j.QueryGraph(c.Request.Context(), assetID, depth)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"asset_id": assetID,
		"depth":    depth,
		"nodes":    nodes,
	})
}

// GetResult returns a single result by ID.
func (s *Server) GetResult(c *gin.Context) {
	id := c.Param("id")

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	asset, err := s.repo.Postgres.GetAssetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found: " + id})
		return
	}
	c.JSON(http.StatusOK, asset)
}

func (s *Server) ListResultEvents(c *gin.Context) {
	id := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	eventType := c.Query("event_type")

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	if _, err := s.repo.Postgres.GetAssetByID(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found: " + id})
		return
	}
	events, err := s.repo.Postgres.QueryAssetEvents(c.Request.Context(), id, "", eventType, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) ListEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	assetID := c.Query("asset_id")
	campaignID := c.Query("campaign_id")
	eventType := c.Query("event_type")

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	events, err := s.repo.Postgres.QueryAssetEvents(c.Request.Context(), assetID, campaignID, eventType, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) UpdateResultStatus(c *gin.Context) {
	id := c.Param("id")
	var req UpdateResultStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !data.ValidAssetStatus(req.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset status: " + req.Status})
		return
	}
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	if _, err := s.repo.Postgres.GetAssetByID(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found: " + id})
		return
	}
	if err := s.repo.UpdateAssetStatus(c.Request.Context(), id, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	asset, err := s.repo.Postgres.GetAssetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": id, "status": req.Status})
		return
	}
	c.JSON(http.StatusOK, asset)
}
