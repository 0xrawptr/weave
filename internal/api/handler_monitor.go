package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Monitor struct {
	ID            string    `json:"id"`
	CampaignID    string    `json:"campaign_id"`
	Name          string    `json:"name"`
	Ports         string    `json:"ports"`
	IntervalHours int       `json:"interval_hours"`
	Status        string    `json:"status"` // active, paused
	LastRunAt     time.Time `json:"last_run_at"`
	NextRunAt     time.Time `json:"next_run_at"`
	RunCount      int       `json:"run_count"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *Server) CreateMonitor(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	var req struct {
		CampaignID    string `json:"campaign_id"`
		Name          string `json:"name"`
		Ports         string `json:"ports"`
		IntervalHours int    `json:"interval_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CampaignID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "campaign_id is required"})
		return
	}
	if req.IntervalHours <= 0 {
		req.IntervalHours = 24
	}
	now := time.Now()
	m := Monitor{
		ID:            generateWorkflowID("monitor"),
		CampaignID:    req.CampaignID,
		Name:          req.Name,
		Ports:         req.Ports,
		IntervalHours: req.IntervalHours,
		Status:        "active",
		LastRunAt:     time.Time{},
		NextRunAt:     now.Add(time.Duration(req.IntervalHours) * time.Hour),
		RunCount:      0,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	_, err := s.repo.Postgres.Exec(c.Request.Context(),
		`INSERT INTO monitors (id, campaign_id, name, ports, interval_hours, status, last_run_at, next_run_at, run_count, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		m.ID, m.CampaignID, m.Name, m.Ports, m.IntervalHours, m.Status, m.LastRunAt, m.NextRunAt, m.RunCount, m.CreatedAt, m.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, m)
}

func (s *Server) ListMonitors(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	rows, err := s.repo.Postgres.Query(c.Request.Context(),
		`SELECT id, campaign_id, name, ports, interval_hours, status, last_run_at, next_run_at, run_count, created_at, updated_at
		 FROM monitors ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	monitors := []Monitor{}
	for rows.Next() {
		var m Monitor
		if err := rows.Scan(&m.ID, &m.CampaignID, &m.Name, &m.Ports, &m.IntervalHours, &m.Status, &m.LastRunAt, &m.NextRunAt, &m.RunCount, &m.CreatedAt, &m.UpdatedAt); err != nil {
			continue
		}
		monitors = append(monitors, m)
	}
	c.JSON(http.StatusOK, gin.H{"monitors": monitors, "total": len(monitors)})
}

func (s *Server) PauseMonitor(c *gin.Context) {
	s.updateMonitorStatus(c, "paused")
}

func (s *Server) ResumeMonitor(c *gin.Context) {
	s.updateMonitorStatus(c, "active")
}

func (s *Server) DeleteMonitor(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	_, _ = s.repo.Postgres.Exec(c.Request.Context(), `DELETE FROM monitors WHERE id = $1`, c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"message": "monitor deleted"})
}

func (s *Server) updateMonitorStatus(c *gin.Context, status string) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}
	_, _ = s.repo.Postgres.Exec(c.Request.Context(),
		`UPDATE monitors SET status = $1, updated_at = NOW() WHERE id = $2`, status, c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"message": "monitor " + status, "id": c.Param("id")})
}

