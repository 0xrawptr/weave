package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

// NeutronExtractor extracts vulnerability findings from neutron output.
type NeutronExtractor struct{}

func (n *NeutronExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type neutronItem struct {
		TemplateID string `json:"template_id"`
		Info       string `json:"info"`
		Severity   string `json:"severity"`
		Target     string `json:"target"`
		Matched    string `json:"matched"`
	}
	type neutronOutput struct {
		Results []neutronItem `json:"results"`
		Total   int           `json:"total"`
	}
	var out neutronOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse neutron result: %w", err)
	}

	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Results {
		itemRaw, _ := json.Marshal(item)
		urlValue := item.Target
		if urlValue == "" {
			urlValue = item.Matched
		}
		if urlValue != "" {
			urlID := data.GenerateID("url", scanTarget, urlValue)
			addEntity(result, entitySet, Entity{
				ID: urlID, Type: "url", Value: urlValue,
				Source: "neutron", TargetID: targetID, RawData: itemRaw,
				Confidence: 1.0, Status: "observed",
			})
		}

		var templateID string
		if item.TemplateID != "" {
			templateID = data.GenerateID("template", scanTarget, item.TemplateID)
			addEntity(result, entitySet, Entity{
				ID: templateID, Type: "template", Value: item.TemplateID,
				Source: "neutron", TargetID: targetID, RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Priority: severityPriority(item.Severity), Status: "confirmed",
			})
		}

		vulnID := data.GenerateID("vuln", scanTarget, item.Target, item.TemplateID, item.Info)
		value := strings.TrimSpace(fmt.Sprintf("%s: %s", item.Severity, item.Info))
		if value == ":" {
			value = "neutron finding"
		}
		addEntity(result, entitySet, Entity{
			ID: vulnID, Type: "vulnerability", Value: value,
			Source: "neutron", TargetID: targetID, RawData: itemRaw,
			Confidence: 1.0, Severity: strings.ToLower(item.Severity),
			Priority: severityPriority(item.Severity), Status: "confirmed",
		})
		if urlValue != "" {
			addRelation(result, relationSet, Relation{
				FromID: data.GenerateID("url", scanTarget, urlValue), ToID: vulnID, Type: RelHasVulnerability,
			})
		}
		if templateID != "" {
			addRelation(result, relationSet, Relation{FromID: templateID, ToID: vulnID, Type: RelDetects})
		}
	}
	return result, nil
}
