package api

import (
	"math"
	"net/http"
	"runtime"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

type DashboardStatsResponse struct {
	TotalAssets      int            `json:"total_assets"`
	AssetsByType     map[string]int `json:"assets_by_type"`
	TodayNewAssets   int            `json:"today_new_assets"`
	ActiveWorkItems  int            `json:"active_work_items"`
	Vulnerabilities  int            `json:"vulnerabilities"`
	Campaigns        int            `json:"campaigns"`
	Batches          int            `json:"batches"`
	Artifacts        int            `json:"artifacts"`
}

type DashboardTrendPoint struct {
	Date   string `json:"date"`
	Assets int    `json:"assets"`
	Vulns  int    `json:"vulns"`
}

type DashboardHealthResponse struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	TemporalOK    bool    `json:"temporal_ok"`
	PostgresOK    bool    `json:"postgres_ok"`
	RedisOK       bool    `json:"redis_ok"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

var serverStartTime = time.Now()

func (s *Server) DashboardStats(c *gin.Context) {
	ctx := c.Request.Context()
	resp := DashboardStatsResponse{}

	if s.repo != nil && s.repo.Postgres != nil {
		db := s.repo.Postgres

		var total int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM assets`).Scan(&total)
		resp.TotalAssets = total

		resp.AssetsByType = map[string]int{}
		rows, err := db.Query(ctx, `SELECT type, COUNT(*) FROM assets GROUP BY type`)
		if err == nil {
			for rows.Next() {
				var typ string
				var cnt int
				if err := rows.Scan(&typ, &cnt); err == nil {
					resp.AssetsByType[typ] = cnt
				}
			}
			rows.Close()
		}

		var today int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM assets WHERE created_at >= CURRENT_DATE`).Scan(&today)
		resp.TodayNewAssets = today

		resp.Vulnerabilities = resp.AssetsByType["vulnerability"]

		var active int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM work_items WHERE status IN ('running','starting','pending')`).Scan(&active)
		resp.ActiveWorkItems = active

		var campaigns int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM campaigns WHERE status = 'active'`).Scan(&campaigns)
		resp.Campaigns = campaigns

		var batches int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM batch_runs`).Scan(&batches)
		resp.Batches = batches
	}

	if s.registry != nil {
		resp.Artifacts = len(s.registry.List())
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) DashboardTrend(c *gin.Context) {
	ctx := c.Request.Context()
	points := make([]DashboardTrendPoint, 0, 7)

	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusOK, gin.H{"points": points})
		return
	}

	db := s.repo.Postgres
	for i := 6; i >= 0; i-- {
		date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		point := DashboardTrendPoint{Date: date}

		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM assets WHERE created_at::date = $1`, date).Scan(&point.Assets)
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM assets WHERE type = 'vulnerability' AND created_at::date = $1`, date).Scan(&point.Vulns)

		points = append(points, point)
	}

	c.JSON(http.StatusOK, gin.H{"points": points})
}

func (s *Server) DashboardHealth(c *gin.Context) {
	ctx := c.Request.Context()
	resp := DashboardHealthResponse{
		UptimeSeconds: int64(time.Since(serverStartTime).Seconds()),
	}

	// Memory from runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// approximate memory percent: Alloc / Sys
	if m.Sys > 0 {
		resp.MemoryPercent = math.Round(float64(m.Alloc)/float64(m.Sys)*10000) / 100
	}

	// CPU cores (informational, not real-time CPU usage)
	resp.CPUPercent = 0

	// Disk
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		used := total - free
		if total > 0 {
			resp.DiskPercent = math.Round(float64(used)/float64(total)*1000) / 10
		}
	}

	// Postgres
	if s.repo != nil && s.repo.Postgres != nil {
		var one int
		resp.PostgresOK = s.repo.Postgres.QueryRow(ctx, `SELECT 1`).Scan(&one) == nil
	}

	// Redis
	if s.repo != nil && s.repo.Redis != nil {
		resp.RedisOK = s.repo.Redis.Ping(ctx) == nil
	}

	// Temporal
	if s.temporal != nil {
		_, err := s.temporal.CheckHealth(ctx, nil)
		resp.TemporalOK = err == nil
	}

	c.JSON(http.StatusOK, resp)
}
