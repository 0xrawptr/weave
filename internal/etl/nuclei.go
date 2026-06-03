package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
				Source: "nuclei", TargetID: targetID, RawData: itemRaw,
				Confidence: 1.0, Status: "observed",
			})
		}

		templateID := data.GenerateID("template", scanTarget, item.TemplateID)
		if item.TemplateID != "" {
			addEntity(result, entitySet, Entity{
				ID: templateID, Type: "template", Value: item.TemplateID,
				Source: "nuclei", TargetID: targetID, RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Priority: severityPriority(item.Severity), Status: "confirmed",
			})
		}

		vulnID := data.GenerateID("vuln", scanTarget, item.Target, item.TemplateID)
		addEntity(result, entitySet, Entity{
			ID: vulnID, Type: "vulnerability",
			Value:  fmt.Sprintf("%s: %s", item.Severity, item.Info),
			Source: "nuclei", TargetID: targetID, RawData: itemRaw,
			Confidence: 1.0, Severity: strings.ToLower(item.Severity),
			Priority: severityPriority(item.Severity), Status: "confirmed",
		})
		if urlValue != "" {
			addRelation(result, relationSet, Relation{
				FromID: data.GenerateID("url", scanTarget, urlValue), ToID: vulnID, Type: RelHasVulnerability,
			})
		}
		if item.TemplateID != "" {
			addRelation(result, relationSet, Relation{
				FromID: templateID, ToID: vulnID, Type: RelDetects,
			})
			if cve := templateCVE(item.TemplateID); cve != "" {
				cveID := data.GenerateID("cve", scanTarget, cve)
				addEntity(result, entitySet, Entity{
					ID: cveID, Type: "cve", Value: cve,
					Source: "nuclei", TargetID: targetID, RawData: itemRaw,
					Confidence: 1.0, Severity: strings.ToLower(item.Severity),
					Priority: severityPriority(item.Severity), Status: "confirmed",
				})
				addRelation(result, relationSet, Relation{
					FromID: vulnID, ToID: cveID, Type: RelRelatesTo,
				})
			}
		}
	}
	return result, nil
}

func addEntity(result *ExtractResult, seen map[string]bool, entity Entity) {
	if entity.ID == "" || seen[entity.ID] {
		return
	}
	seen[entity.ID] = true
	result.Entities = append(result.Entities, entity)
}

func addRelation(result *ExtractResult, seen map[string]bool, rel Relation) {
	if rel.FromID == "" || rel.ToID == "" || rel.Type == "" {
		return
	}
	key := rel.FromID + "|" + rel.Type + "|" + rel.ToID
	if seen[key] {
		return
	}
	seen[key] = true
	result.Relations = append(result.Relations, rel)
}

func templateCVE(templateID string) string {
	upper := strings.ToUpper(strings.TrimSpace(templateID))
	if strings.HasPrefix(upper, "CVE-") {
		return upper
	}
	return ""
}

func severityPriority(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 50
	case "low":
		return 30
	case "info":
		return 10
	default:
		return 0
	}
}
