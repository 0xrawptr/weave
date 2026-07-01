package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// FOFA search
func (s *Server) FofaSearch(c *gin.Context) {
	var req struct {
		Query string `json:"query"`
		Size  int    `json:"size"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query field is required"})
		return
	}
	if req.Size <= 0 || req.Size > 100 {
		req.Size = 10
	}

	email := s.cfg.SDK.CyberHub.Endpoint
	key := s.cfg.SDK.CyberHub.APIKey
	if email == "" || key == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "FOFA credentials not configured (sdk.cyberhub)"})
		return
	}

	query := base64.StdEncoding.EncodeToString([]byte(req.Query))
	apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d",
		url.QueryEscape(email), url.QueryEscape(key), query, req.Size)

	resp, err := http.Get(apiURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "FOFA API request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(body, &result)

	c.JSON(http.StatusOK, gin.H{"source": "fofa", "query": req.Query, "result": result})
}

// GitHub search
func (s *Server) GitHubSearch(c *gin.Context) {
	var req struct {
		Keyword string `json:"keyword"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "keyword field is required"})
		return
	}

	token := strings.TrimSpace(s.cfg.SDK.CyberHub.APIKey)
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=10",
		url.QueryEscape(req.Keyword))

	httpReq, _ := http.NewRequestWithContext(c.Request.Context(), "GET", apiURL, nil)
	httpReq.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "GitHub API request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(body, &result)

	c.JSON(http.StatusOK, gin.H{"source": "github", "keyword": req.Keyword, "result": result})
}

// GeoIP enrichment
func (s *Server) EnrichGeoIP(c *gin.Context) {
	if s.repo == nil || s.repo.Postgres == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data store not available"})
		return
	}

	var req struct {
		IPs    []string `json:"ips"`
		Limit  int      `json:"limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.IPs) == 0 {
		// Get IPs from assets that don't have geo data yet
		rows, err := s.repo.Postgres.Query(c.Request.Context(),
			`SELECT id, value FROM assets WHERE type = 'ip' AND (raw_data IS NULL OR raw_data::text !~ 'country') LIMIT $1`,
			max(req.Limit, 50))
		if err == nil {
			for rows.Next() {
				var id, value string
				if err := rows.Scan(&id, &value); err == nil {
					req.IPs = append(req.IPs, value)
				}
			}
			rows.Close()
		}
	}

	enriched := 0
	for _, ip := range req.IPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		// Use ip-api.com (free, no key required)
		resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=country,city,isp,org,as")
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var geo map[string]interface{}
		if json.Unmarshal(body, &geo) == nil {
			geoJSON, _ := json.Marshal(geo)
			// Store geo as raw_data on asset
			_, _ = s.repo.Postgres.Exec(c.Request.Context(),
				`UPDATE assets SET raw_data = $1 WHERE type = 'ip' AND value = $2`,
				geoJSON, ip)
			enriched++
		}
	}

	c.JSON(http.StatusOK, gin.H{"enriched": enriched, "ips": len(req.IPs)})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func init() {
	_ = bytes.MinRead
	_ = fmt.Sprintf
}
