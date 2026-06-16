package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SprayExtractor extracts discovered/checkable URLs from spray output.
type SprayExtractor struct{}

type sprayFrameworkItem struct {
	Name        string                 `json:"name"`
	Product     string                 `json:"product,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	CPE         string                 `json:"cpe,omitempty"`
	IsFocus     bool                   `json:"is_focus,omitempty"`
	MatchDetail map[string]interface{} `json:"match_detail,omitempty"`
}

type sprayExtractItem struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity,omitempty"`
	Values   []string `json:"values,omitempty"`
}

func (s *SprayExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type sprayItem struct {
		URL           string               `json:"url"`
		StatusCode    int                  `json:"status_code"`
		Title         string               `json:"title,omitempty"`
		ContentType   string               `json:"content_type,omitempty"`
		ContentLength int64                `json:"content_length,omitempty"`
		BodyHash      string               `json:"body_hash,omitempty"`
		BodySimhash   string               `json:"body_simhash,omitempty"`
		FaviconHash   string               `json:"favicon_hash,omitempty"`
		Location      string               `json:"location,omitempty"`
		Valid         *bool                `json:"valid,omitempty"`
		Fuzzy         bool                 `json:"fuzzy,omitempty"`
		Reason        string               `json:"reason,omitempty"`
		Frameworks    []sprayFrameworkItem `json:"frameworks,omitempty"`
		Extracts      []sprayExtractItem   `json:"extracts,omitempty"`
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
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)

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
		urlTarget := targetForURL(candidate.canonical)
		urlID := assetID("url", urlTarget.Value)
		urlEntity := Entity{
			ID: urlID, Type: "url", Value: candidate.canonical,
			Source: "spray", RawData: candidate.raw,
			Confidence: httpConfidence(candidate.item.StatusCode, quality),
			Status:     qualityStatus(quality, "observed"),
			Quality:    &quality,
			Reason:     qualityReason(quality),
		}
		applyTarget(&urlEntity, urlTarget)
		addEntity(result, entitySet, urlEntity)
		for _, framework := range candidate.item.Frameworks {
			name := strings.TrimSpace(framework.Name)
			if name == "" {
				continue
			}
			product := strings.TrimSpace(framework.Product)
			if product == "" {
				product = name
			}
			fpID := evidenceID("fingerprint", urlTarget, name)
			fpEntity := Entity{
				ID: fpID, Type: "fingerprint", Value: name,
				Source: "spray", RawData: candidate.raw,
				Product: product, Version: framework.Version, Tags: framework.Tags,
				CPEs:       nonEmptyStrings(framework.CPE),
				Confidence: sprayFingerprintConfidence(len(framework.MatchDetail) > 0), Status: "observed",
			}
			applyTarget(&fpEntity, urlTarget)
			addEntity(result, entitySet, fpEntity)
			addRelation(result, relationSet, Relation{FromID: urlID, ToID: fpID, Type: RelHasFingerprint})
		}
		for _, extracted := range candidate.item.Extracts {
			name := strings.TrimSpace(extracted.Name)
			for _, value := range extracted.Values {
				value = strings.TrimSpace(value)
				if name == "" || value == "" {
					continue
				}
				extractedID := evidenceID("extracted", urlTarget, name, value)
				extractedEntity := Entity{
					ID: extractedID, Type: "extracted", Value: value,
					Source: "spray", RawData: candidate.raw,
					Severity:   strings.ToLower(extracted.Severity),
					Confidence: 0.75, Status: "observed", Tags: []string{name},
				}
				applyTarget(&extractedEntity, urlTarget)
				addEntity(result, entitySet, extractedEntity)
				addRelation(result, relationSet, Relation{FromID: urlID, ToID: extractedID, Type: RelRelatesTo})
			}
		}
	}
	return result, nil
}

func sprayFingerprintConfidence(hasMatchDetail bool) float64 {
	if hasMatchDetail {
		return 0.85
	}
	return 0.75
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
