package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// PlanTarget returns planner recommendations for the current target state.
func (s *Server) PlanTarget(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target query parameter is required"})
		return
	}
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	if s.planner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "planner not available"})
		return
	}

	actions, err := s.planner.PlanForTarget(c.Request.Context(), target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"target":  target,
		"actions": actions,
	})
}
