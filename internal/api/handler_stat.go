package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (s *Server) ListArtifactStats(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	stats, err := s.repo.GetArtifactStats(
		c.Request.Context(),
		c.Query("campaign_id"),
		c.Query("workflow_id"),
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
		"stats":  stats,
		"total":  len(stats),
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) ArtifactStatsSummary(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	summary, err := s.repo.GetArtifactStatSummary(
		c.Request.Context(),
		c.Query("campaign_id"),
		c.Query("workflow_id"),
		c.Query("artifact"),
		c.Query("target"),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"summary": summary,
		"total":   len(summary),
	})
}
