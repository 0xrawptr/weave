package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/0xrawptr/weave/internal/data/dbsqlc"
	"github.com/gin-gonic/gin"
)

type ICPQueryRequest struct {
	Company string `json:"company"`
	Type    string `json:"type"` // web, app, all
}

type ICPDomain struct {
	Domain      string `json:"domain"`
	CompanyName string `json:"company_name"`
	ICPNumber   string `json:"icp_number"`
	SiteName    string `json:"site_name"`
}

func (s *Server) ICPQuery(c *gin.Context) {
	var req ICPQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Company == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company field is required"})
		return
	}

	domains, err := queryICPAPI(req.Company)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "ICP query failed: " + err.Error()})
		return
	}

	// Save domains as assets
	saved := 0
	if s.repo != nil && s.repo.SQLC != nil {
		for _, d := range domains {
			id := generateWorkflowID("icp-domain")
			campaignID := c.Query("campaign_id")
			data, _ := json.Marshal(d)
			_ = s.repo.SQLC.CreateAsset(c.Request.Context(), dbsqlc.CreateAssetParams{
				ID: id, CampaignID: campaignID, Type: "domain",
				Value: d.Domain, Source: "icp",
				RawData: data, Confidence: 0.8,
				Status: "observed", Lifecycle: "active",
			})
			saved++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"company":  req.Company,
		"domains":  domains,
		"total":    len(domains),
		"saved":    saved,
	})
}

func queryICPAPI(company string) ([]ICPDomain, error) {
	// Use beian.miit.gov.cn or a third-party ICP API
	apiURL := "https://api.beianapi.com/query"
	params := url.Values{}
	params.Set("keyword", company)
	params.Set("page", "1")

	resp, err := http.Get(apiURL + "?" + params.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Items []ICPDomain `json:"items"`
	}
	json.Unmarshal(body, &result)
	return result.Items, nil
}

