package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

// SprayExtractor extracts discovered/checkable URLs from spray output.
type SprayExtractor struct{}

func (s *SprayExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type sprayItem struct {
		URL        string `json:"url"`
		StatusCode int    `json:"status_code"`
	}
	type sprayOutput struct {
		Results []sprayItem `json:"results"`
		Total   int         `json:"total"`
	}
	var out sprayOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse spray result: %w", err)
	}

	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	entitySet := make(map[string]bool)
	for _, item := range out.Results {
		if item.URL == "" {
			continue
		}
		itemRaw, _ := json.Marshal(item)
		urlID := data.GenerateID("url", scanTarget, item.URL)
		addEntity(result, entitySet, Entity{
			ID: urlID, Type: "url", Value: item.URL,
			Source: "spray", TargetID: targetID, RawData: itemRaw,
			Confidence: statusConfidence(item.StatusCode), Status: "observed",
			Priority: sprayURLPriority(item.URL),
		})
	}
	return result, nil
}

func statusConfidence(statusCode int) float64 {
	if statusCode >= 200 && statusCode < 400 {
		return 0.9
	}
	if statusCode >= 400 && statusCode < 500 {
		return 0.6
	}
	if statusCode >= 500 {
		return 0.5
	}
	return 0.7
}

func sprayURLPriority(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	p := strings.ToLower(u.Path)
	switch {
	case strings.Contains(p, "/actuator/env"),
		strings.Contains(p, "/actuator/configprops"),
		strings.Contains(p, "/actuator/heapdump"),
		strings.Contains(p, "/actuator/jolokia"),
		strings.Contains(p, "/actuator/logfile"):
		return 100
	case strings.Contains(p, "/actuator"),
		strings.Contains(p, "/v3/api-docs"),
		strings.Contains(p, "/swagger"),
		strings.Contains(p, "/api-docs"),
		strings.Contains(p, "/openapi"):
		return 80
	case strings.Contains(p, "/admin"),
		strings.Contains(p, "/login"),
		strings.Contains(p, "/console"),
		strings.Contains(p, "/manager"),
		strings.Contains(p, "/debug"),
		strings.Contains(p, "/metrics"),
		strings.Contains(p, "/config"),
		strings.Contains(p, "/env"):
		return 60
	default:
		return 10
	}
}
