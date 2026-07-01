package api

import (
	"net/http"

	"github.com/0xrawptr/weave/internal/data/dbsqlc"
	"github.com/gin-gonic/gin"
)

func paginationParams(c *gin.Context, defaultLimit, defaultOffset int) (int, int) {
	limit := defaultLimit
	offset := defaultOffset
	if v := c.Query("limit"); v != "" {
		if n, ok := parseInt(v); ok && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, ok := parseInt(v); ok && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func parseInt(s string) (int, bool) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func (s *Server) CreatePolicy(c *gin.Context) {
	if s.repo == nil || s.repo.SQLC == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Ports       string `json:"ports"`
		Threads     int    `json:"threads"`
		SprayDict   string `json:"spray_dict"`
		NucleiTags  string `json:"nuclei_tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := generateWorkflowID("policy")
	if err := s.repo.SQLC.CreatePolicy(c.Request.Context(), dbsqlc.CreatePolicyParams{
		ID: id, Name: req.Name, Description: req.Description,
		Ports: req.Ports, Threads: int32(req.Threads),
		SprayDict: req.SprayDict, NucleiTags: req.NucleiTags,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "name": req.Name})
}

func (s *Server) ListPolicies(c *gin.Context) {
	if s.repo == nil || s.repo.SQLC == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	limit, offset := paginationParams(c, 50, 0)
	policies, err := s.repo.SQLC.ListPolicies(c.Request.Context(), dbsqlc.ListPoliciesParams{
		Limit: int32(limit), Offset: int32(offset),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

func (s *Server) GetPolicy(c *gin.Context) {
	if s.repo == nil || s.repo.SQLC == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	policy, err := s.repo.SQLC.GetPolicy(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy)
}

func (s *Server) UpdatePolicy(c *gin.Context) {
	if s.repo == nil || s.repo.SQLC == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Ports       string `json:"ports"`
		Threads     int    `json:"threads"`
		SprayDict   string `json:"spray_dict"`
		NucleiTags  string `json:"nuclei_tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.repo.SQLC.UpdatePolicy(c.Request.Context(), dbsqlc.UpdatePolicyParams{
		ID: c.Param("id"), Name: req.Name, Description: req.Description,
		Ports: req.Ports, Threads: int32(req.Threads),
		SprayDict: req.SprayDict, NucleiTags: req.NucleiTags,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy updated"})
}

func (s *Server) DeletePolicy(c *gin.Context) {
	if s.repo == nil || s.repo.SQLC == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	if err := s.repo.SQLC.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}
