package etl

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xrawptr/weave/internal/data"
)

type FingersExtractor struct{}

func (f *FingersExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type fingersItem struct {
		Name    string   `json:"name"`
		Target  string   `json:"target,omitempty"`
		Product string   `json:"product,omitempty"`
		Version string   `json:"version,omitempty"`
		Tags    []string `json:"tags,omitempty"`
		Sources []string `json:"sources,omitempty"`
		CPE     string   `json:"cpe,omitempty"`
		Focus   bool     `json:"focus,omitempty"`
	}
	type fingersOutput struct {
		Frameworks []fingersItem `json:"frameworks"`
		Count      int           `json:"count"`
	}
	var out fingersOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse fingers result: %w", err)
	}
	result := &ExtractResult{}
	targetID := data.TargetID(scanTarget)
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Frameworks {
		itemRaw, _ := json.Marshal(item)
		fpID := data.GenerateID("fingerprint", scanTarget, item.Name)
		var cpes []string
		if item.CPE != "" {
			cpes = []string{item.CPE}
		}
		addEntity(result, entitySet, Entity{
			ID: fpID, Type: "fingerprint", Value: item.Name,
			Source: "fingers", TargetID: targetID, RawData: itemRaw,
			Product: item.Product, Version: item.Version, Tags: item.Tags,
			CPEs: cpes, Confidence: 0.85, Status: "observed",
		})
		if item.Target == "" {
			continue
		}
		urlValue := item.Target
		var urlQuality *Quality
		if canonical, quality := buildHTTPQuality(HTTPQualityInput{URL: urlValue}); canonical != "" {
			urlValue = canonical
			urlQuality = &quality
		}
		urlID := data.GenerateID("url", scanTarget, urlValue)
		addEntity(result, entitySet, Entity{
			ID: urlID, Type: "url", Value: urlValue,
			Source: "fingers", TargetID: targetID, RawData: itemRaw,
			Confidence: 0.9, Status: "observed", Quality: urlQuality,
		})
		addRelation(result, relationSet, Relation{FromID: urlID, ToID: fpID, Type: RelHasFingerprint})
	}
	return result, nil
}
