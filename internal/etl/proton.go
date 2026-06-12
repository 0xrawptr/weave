package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type ProtonExtractor struct{}

type protonMatchEvent struct {
	Value  string `json:"value"`
	Line   int    `json:"line"`
	Offset int    `json:"offset,omitempty"`
}

type protonItem struct {
	TemplateID   string                        `json:"template-id"`
	TemplateName string                        `json:"template-name"`
	Severity     string                        `json:"severity"`
	FilePath     string                        `json:"file"`
	Matches      map[string][]protonMatchEvent `json:"matches,omitempty"`
	Extracts     []protonMatchEvent            `json:"extracts,omitempty"`
}

type protonOutput struct {
	Results []protonItem `json:"results"`
	Total   int          `json:"total"`
}

func (p *ProtonExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	var out protonOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse proton result: %w", err)
	}

	target := targetForValue(scanTarget)
	result := &ExtractResult{}
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)

	anchorID := target.ID
	if scanTarget != "" {
		anchor := Entity{
			ID: anchorID, Type: target.Type, Value: target.Value,
			Source: "proton", Confidence: 1.0, Status: "observed",
		}
		applyTarget(&anchor, target)
		addEntity(result, entitySet, anchor)
	}

	for _, item := range out.Results {
		itemRaw, _ := json.Marshal(item)
		value := protonFindingValue(item.TemplateID, item.TemplateName, item.FilePath)
		if value == "" {
			value = "proton sensitive finding"
		}
		entity := Entity{
			ID:   evidenceID("credential", target, value),
			Type: "credential", Value: value,
			Source: "proton", RawData: itemRaw,
			Confidence: 1.0, Severity: strings.ToLower(item.Severity),
			Status: "confirmed",
			Reason: protonFindingReason(item),
		}
		applyTarget(&entity, target)
		addEntity(result, entitySet, entity)
		if anchorID != "" {
			addRelation(result, relationSet, Relation{FromID: anchorID, ToID: entity.ID, Type: RelHasCredential})
		}
		if item.TemplateID != "" {
			templateID := evidenceID("template", target, item.TemplateID)
			template := Entity{
				ID: templateID, Type: "template", Value: item.TemplateID,
				Source: "proton", RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity), Status: "confirmed",
			}
			applyTarget(&template, target)
			addEntity(result, entitySet, template)
			addRelation(result, relationSet, Relation{FromID: templateID, ToID: entity.ID, Type: RelDetects})
		}
	}
	return result, nil
}

func protonFindingValue(templateID, templateName, filePath string) string {
	parts := make([]string, 0, 2)
	if templateID != "" {
		parts = append(parts, templateID)
	} else if templateName != "" {
		parts = append(parts, templateName)
	}
	if filePath != "" {
		parts = append(parts, filePath)
	}
	return strings.Join(parts, " @ ")
}

func protonFindingReason(item protonItem) string {
	if item.TemplateID == "" && item.FilePath == "" {
		return "proton matched sensitive information"
	}
	return strings.TrimSpace(fmt.Sprintf("proton matched %s in %s", item.TemplateID, item.FilePath))
}
