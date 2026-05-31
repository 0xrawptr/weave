package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ListResults returns a paginated list of results from the data store.
func (s *Server) ListResults(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	targetID := c.Query("target_id")
	assetType := c.Query("type")

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	assets, err := s.repo.Postgres.QueryAssets(c.Request.Context(), targetID, assetType, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": assets,
		"total":   len(assets),
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

	assets, err := s.repo.Postgres.QueryAssets(c.Request.Context(), "", "", 1, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Simple linear search — in production, add a dedicated GetByID method
	for _, a := range assets {
		if a.ID == id {
			c.JSON(http.StatusOK, a)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "result not found"})
}
