package api

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/gin-gonic/gin"
)

var exportTypes = map[string]bool{
	"ip": true, "port": true, "service": true, "url": true,
}

func (s *Server) ExportBatch(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	batchID := c.Param("id")
	assetType := strings.ToLower(strings.TrimSpace(c.Query("type")))
	if assetType == "" || !exportTypes[assetType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("type is required, one of: ip,port,service,url")})
		return
	}

	format := strings.ToLower(strings.TrimSpace(c.DefaultQuery("format", "json")))
	if format != "csv" && format != "json" {
		format = "json"
	}

	// Get campaign_id from batch
	campaignID := ""
	if run, err := s.repo.GetBatchRun(c.Request.Context(), batchID); err == nil && run != nil {
		campaignID = run.CampaignID
	}

	results, err := s.listFilteredAssets(c.Request.Context(), &data.WorkItemFilter{
		CampaignID: campaignID,
		BatchID:    batchID,
	}, assetType, 100000, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if format == "csv" {
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s.csv", batchID, assetType))
		csvWriter := csv.NewWriter(c.Writer)
		_ = csvWriter.Write([]string{"type", "value", "source", "status", "first_seen", "last_seen"})
		for _, r := range results {
			_ = csvWriter.Write([]string{r.Type, r.Value, r.Source, r.Status, formatTimeStr(r.FirstSeen), formatTimeStr(r.LastSeen)})
		}
		csvWriter.Flush()
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"batch_id": batchID,
		"type":     assetType,
		"format":   "json",
		"count":    len(results),
		"results":  results,
	})
}

func (s *Server) listFilteredAssets(ctx context.Context, filter *data.WorkItemFilter, assetType string, limit, offset int) ([]data.Asset, error) {
	query := `SELECT id, campaign_id, type, value, source, status, lifecycle_status, confidence, first_seen, last_seen, created_at FROM assets WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if filter.CampaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, filter.CampaignID)
		argIdx++
	}
	if assetType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, assetType)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.repo.Postgres.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []data.Asset
	for rows.Next() {
		var a data.Asset
		if err := rows.Scan(&a.ID, &a.CampaignID, &a.Type, &a.Value, &a.Source, &a.Status, &a.Lifecycle, &a.Confidence, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
			continue
		}
		results = append(results, a)
	}
	return results, nil
}

func formatTimeStr(t interface{}) string {
	switch v := t.(type) {
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

