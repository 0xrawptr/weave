package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListArtifacts returns all registered artifacts with their schemas.
func (s *Server) ListArtifacts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"artifacts": s.registry.List(),
	})
}

// GetArtifact returns a single artifact's details.
func (s *Server) GetArtifact(c *gin.Context) {
	name := c.Param("name")
	a, err := s.registry.Get(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"name":          a.Name(),
		"input_schema":  a.InputSchema(),
		"output_schema": a.OutputSchema(),
	})
}
