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
		TemplateID     string `json:"template_id"`
		TemplateName   string `json:"template_name,omitempty"`
		Description    string `json:"description,omitempty"`
		Severity       string `json:"severity"`
		Target         string `json:"target"`
		Tags           string `json:"tags,omitempty"`
		Matched        bool   `json:"matched"`
		Classification *struct {
			CVEID          string  `json:"cve-id,omitempty"`
			CWEID          string  `json:"cwe-id,omitempty"`
			CVSSMetrics    string  `json:"cvss-metrics,omitempty"`
			CVSSScore      float64 `json:"cvss-score,omitempty"`
			EPSSScore      float64 `json:"epss-score,omitempty"`
			EPSSPercentile float64 `json:"epss-percentile,omitempty"`
			CPE            string  `json:"cpe,omitempty"`
		} `json:"classification,omitempty"`
		Events []struct {
			Matched string `json:"matched,omitempty"`
		} `json:"events,omitempty"`
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
	targetID := data.TargetID(scanTarget)
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Results {
		itemRaw, _ := json.Marshal(item)
		urlValue := item.Target
		if urlValue == "" && len(item.Events) > 0 {
			urlValue = item.Events[0].Matched
		}
		if urlValue != "" {
			var urlQuality *Quality
			if canonical, quality := buildHTTPQuality(HTTPQualityInput{URL: urlValue}); canonical != "" {
				urlValue = canonical
				urlQuality = &quality
			}
			urlID := data.GenerateID("url", scanTarget, urlValue)
			addEntity(result, entitySet, Entity{
				ID: urlID, Type: "url", Value: urlValue,
				Source: "neutron", TargetID: targetID, RawData: itemRaw,
				Confidence: 1.0, Status: "observed", Quality: urlQuality,
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
				Tags: splitCSV(item.Tags),
			})
		}

		info := firstNonEmpty(item.TemplateName, item.Description, item.TemplateID)
		vulnID := data.GenerateID("vuln", scanTarget, item.Target, item.TemplateID, info)
		value := strings.TrimSpace(fmt.Sprintf("%s: %s", item.Severity, info))
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
		if item.Classification != nil {
			for _, cve := range nucleiCVEs(item.TemplateID, []string{item.Classification.CVEID}) {
				cveID := data.GenerateID("cve", scanTarget, cve)
				addEntity(result, entitySet, Entity{
					ID: cveID, Type: "cve", Value: cve,
					Source: "neutron", TargetID: targetID, RawData: itemRaw,
					Confidence: 1.0, Severity: strings.ToLower(item.Severity),
					Priority: severityPriority(item.Severity), Status: "confirmed",
					CVEIntel: []CVEInfo{{
						ID:             cve,
						EPSS:           item.Classification.EPSSScore,
						EPSSPercentile: item.Classification.EPSSPercentile,
						CVSSScore:      item.Classification.CVSSScore,
						CVSSVector:     item.Classification.CVSSMetrics,
						CPEs:           nonEmptyStrings(item.Classification.CPE),
						CWEs:           nonEmptyStrings(strings.ToUpper(strings.TrimSpace(item.Classification.CWEID))),
					}},
				})
				addRelation(result, relationSet, Relation{FromID: vulnID, ToID: cveID, Type: RelRelatesTo})
				if templateID != "" {
					addRelation(result, relationSet, Relation{FromID: cveID, ToID: templateID, Type: RelHasTemplate})
				}
				if item.Classification.CPE != "" {
					cpeID := data.GenerateID("cpe", scanTarget, item.Classification.CPE)
					addEntity(result, entitySet, Entity{
						ID: cpeID, Type: "cpe", Value: item.Classification.CPE,
						Source: "neutron", TargetID: targetID, RawData: itemRaw,
						Confidence: 0.8, Status: "confirmed",
					})
					addRelation(result, relationSet, Relation{FromID: cveID, ToID: cpeID, Type: RelHasCPE})
				}
				if cwe := strings.ToUpper(strings.TrimSpace(item.Classification.CWEID)); cwe != "" {
					cweID := data.GenerateID("cwe", scanTarget, cwe)
					addEntity(result, entitySet, Entity{
						ID: cweID, Type: "cwe", Value: cwe,
						Source: "neutron", TargetID: targetID, RawData: itemRaw,
						Confidence: 0.8, Status: "confirmed",
					})
					addRelation(result, relationSet, Relation{FromID: cveID, ToID: cweID, Type: RelHasCWE})
				}
			}
		}
	}
	return result, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
