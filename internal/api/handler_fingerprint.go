package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

type FingerprintRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Rule        string `json:"rule"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

func (s *Server) ListFingerprints(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	rows, err := s.repo.Postgres.Query(c.Request.Context(), `SELECT id, name, rule, type, description FROM fingerprints ORDER BY name LIMIT 200`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	fingerprints := []FingerprintRule{}
	for rows.Next() {
		var f FingerprintRule
		if err := rows.Scan(&f.ID, &f.Name, &f.Rule, &f.Type, &f.Description); err != nil {
			continue
		}
		fingerprints = append(fingerprints, f)
	}
	c.JSON(http.StatusOK, gin.H{"fingerprints": fingerprints, "total": len(fingerprints)})
}

func (s *Server) CreateFingerprint(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	var f FingerprintRule
	if err := c.ShouldBindJSON(&f); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if f.ID == "" {
		f.ID = generateWorkflowID("fp")
	}
	if f.Type == "" {
		f.Type = "http"
	}

	ruleJSON, _ := json.Marshal(f)
	_, err := s.repo.Postgres.Exec(c.Request.Context(),
		`INSERT INTO fingerprints (id, name, rule, type, description)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET name=$2, rule=$3, type=$4, description=$5`,
		f.ID, f.Name, string(ruleJSON), f.Type, f.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, f)
}

func (s *Server) DeleteFingerprint(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	_, _ = s.repo.Postgres.Exec(c.Request.Context(), `DELETE FROM fingerprints WHERE id = $1`, c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"message": "fingerprint deleted"})
}

func (s *Server) ListPoCs(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	rows, err := s.repo.Postgres.Query(c.Request.Context(), `SELECT id, name, description, type, severity FROM pocs ORDER BY name LIMIT 200`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"pocs": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	pocs := []map[string]string{}
	for rows.Next() {
		var id, name, desc, typ, severity string
		if err := rows.Scan(&id, &name, &desc, &typ, &severity); err != nil {
			continue
		}
		pocs = append(pocs, map[string]string{
			"id": id, "name": name, "description": desc, "type": typ, "severity": severity,
		})
	}
	c.JSON(http.StatusOK, gin.H{"pocs": pocs, "total": len(pocs)})
}

func (s *Server) SyncPoCs(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "sync triggered (no-op — PoCs managed by SDK)", "synced": 0})
}

