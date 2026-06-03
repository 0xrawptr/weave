package etl

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xrawptr/weave/internal/data"
)

type NucleiExtractor struct{}

func (n *NucleiExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type nucleiItem struct {
		TemplateID string `json:"template_id"`
		Info       string `json:"info"`
		Severity   string `json:"severity"`
		Target     string `json:"target"`
		Matched    string `json:"matched"`
	}
	type nucleiOutput struct {
		Results []nucleiItem `json:"results"`
		Total   int          `json:"total"`
	}
	var out nucleiOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse nuclei result: %w", err)
	}
	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	for _, item := range out.Results {
		itemRaw, _ := json.Marshal(item)
		vulnID := data.GenerateID("vuln", scanTarget, item.Target, item.TemplateID)
		result.Entities = append(result.Entities, Entity{
			ID: vulnID, Type: "vulnerability",
			Value:  fmt.Sprintf("%s: %s", item.Severity, item.Info),
			Source: "nuclei", TargetID: targetID, RawData: itemRaw,
		})
	}
	return result, nil
}
