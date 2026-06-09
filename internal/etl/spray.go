package etl

import (
	"context"
	"encoding/json"
	"fmt"
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
		URL           string `json:"url"`
		StatusCode    int    `json:"status_code"`
		Title         string `json:"title,omitempty"`
		ContentType   string `json:"content_type,omitempty"`
		ContentLength int64  `json:"content_length,omitempty"`
		BodyHash      string `json:"body_hash,omitempty"`
		BodySimhash   string `json:"body_simhash,omitempty"`
		FaviconHash   string `json:"favicon_hash,omitempty"`
		Location      string `json:"location,omitempty"`
		Valid         *bool  `json:"valid,omitempty"`
		Fuzzy         bool   `json:"fuzzy,omitempty"`
		Reason        string `json:"reason,omitempty"`
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

	type candidate struct {
		item      sprayItem
		raw       []byte
		canonical string
		quality   Quality
	}
	candidates := make([]candidate, 0, len(out.Results))
	for _, item := range out.Results {
		if item.URL == "" {
			continue
		}
		itemRaw, _ := json.Marshal(item)
		canonical, quality := buildHTTPQuality(HTTPQualityInput{
			URL:           item.URL,
			StatusCode:    item.StatusCode,
			Title:         item.Title,
			ContentType:   item.ContentType,
			ContentLength: item.ContentLength,
			BodyHash:      item.BodyHash,
			BodySimhash:   item.BodySimhash,
			FaviconHash:   item.FaviconHash,
			Location:      item.Location,
		})
		if canonical == "" {
			continue
		}
		applySpraySDKQuality(&quality, item.Valid, item.Fuzzy, item.Reason)
		candidates = append(candidates, candidate{item: item, raw: itemRaw, canonical: canonical, quality: quality})
	}

	for _, candidate := range candidates {
		quality := candidate.quality
		if !persistSprayURL(quality) {
			continue
		}
		urlID := data.GenerateID("url", scanTarget, candidate.canonical)
		addEntity(result, entitySet, Entity{
			ID: urlID, Type: "url", Value: candidate.canonical,
			Source: "spray", TargetID: targetID, RawData: candidate.raw,
			Confidence: httpConfidence(candidate.item.StatusCode, quality),
			Status:     qualityStatus(quality, "observed"),
			Priority:   qualityPriority(sprayURLPriority(candidate.canonical), quality),
			Quality:    &quality,
			Reason:     qualityReason(quality),
		})
	}
	return result, nil
}

func persistSprayURL(quality Quality) bool {
	return !quality.Noise
}

func applySpraySDKQuality(quality *Quality, valid *bool, fuzzy bool, reason string) {
	reason = strings.TrimSpace(reason)
	if valid != nil && !*valid {
		quality.Layer = "noise"
		quality.Noise = true
		quality.Reasons = append(quality.Reasons, "sdk_invalid")
	}
	if fuzzy && quality.Layer != "critical" {
		quality.Layer = "noise"
		quality.Noise = true
		quality.Reasons = append(quality.Reasons, "sdk_fuzzy")
	}
	if reason != "" {
		quality.Reasons = append(quality.Reasons, "sdk_reason:"+reason)
	}
}

func sprayURLPriority(rawURL string) int {
	_, meta, _ := normalizeURL(rawURL)
	p := meta.Path
	switch {
	case highRiskPath(p):
		return 100
	case interestingPath(p) && (containsAny(p, "/actuator", "/v3/api-docs", "/swagger", "/api-docs", "/openapi")):
		return 80
	case interestingPath(p):
		return 60
	default:
		return 10
	}
}

func qualityReason(quality Quality) string {
	if len(quality.Reasons) == 0 {
		return quality.Layer
	}
	return quality.Layer + ": " + joinReasons(quality.Reasons)
}

func joinReasons(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ","
		}
		out += value
	}
	return out
}

func containsAny(value string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
