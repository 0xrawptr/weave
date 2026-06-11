package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Results {
		itemRaw, _ := json.Marshal(item)
		urlValue := item.Target
		if urlValue == "" && len(item.Events) > 0 {
			urlValue = item.Events[0].Matched
		}
		target := targetForValue(scanTarget)
		urlID := ""
		if urlValue != "" {
			var urlQuality *Quality
			if canonical, quality := buildHTTPQuality(HTTPQualityInput{URL: urlValue}); canonical != "" {
				urlValue = canonical
				urlQuality = &quality
			}
			target = targetForURL(urlValue)
			urlID = assetID("url", target.Value)
			urlEntity := Entity{
				ID: urlID, Type: "url", Value: urlValue,
				Source: "neutron", RawData: itemRaw,
				Confidence: 1.0, Status: "observed", Quality: urlQuality,
			}
			applyTarget(&urlEntity, target)
			addEntity(result, entitySet, urlEntity)
		}

		var templateID string
		if item.TemplateID != "" {
			templateID = evidenceID("template", target, item.TemplateID)
			templateEntity := Entity{
				ID: templateID, Type: "template", Value: item.TemplateID,
				Source: "neutron", RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Priority: severityPriority(item.Severity), Status: "confirmed",
				Tags: splitCSV(item.Tags),
			}
			applyTarget(&templateEntity, target)
			addEntity(result, entitySet, templateEntity)
		}

		info := firstNonEmpty(item.TemplateName, item.Description, item.TemplateID)
		vulnID := evidenceID("vuln", target, item.Target, item.TemplateID, info)
		value := strings.TrimSpace(fmt.Sprintf("%s: %s", item.Severity, info))
		if value == ":" {
			value = "neutron finding"
		}
		vulnEntity := Entity{
			ID: vulnID, Type: "vulnerability", Value: value,
			Source: "neutron", RawData: itemRaw,
			Confidence: 1.0, Severity: strings.ToLower(item.Severity),
			Priority: severityPriority(item.Severity), Status: "confirmed",
		}
		applyTarget(&vulnEntity, target)
		addEntity(result, entitySet, vulnEntity)
		if urlID != "" {
			addRelation(result, relationSet, Relation{
				FromID: urlID, ToID: vulnID, Type: RelHasVulnerability,
			})
		}
		if templateID != "" {
			addRelation(result, relationSet, Relation{FromID: templateID, ToID: vulnID, Type: RelDetects})
		}
		if item.Classification != nil {
			for _, cve := range nucleiCVEs(item.TemplateID, []string{item.Classification.CVEID}) {
				cveID := evidenceID("cve", target, cve)
				cveEntity := Entity{
					ID: cveID, Type: "cve", Value: cve,
					Source: "neutron", RawData: itemRaw,
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
				}
				applyTarget(&cveEntity, target)
				addEntity(result, entitySet, cveEntity)
				addRelation(result, relationSet, Relation{FromID: vulnID, ToID: cveID, Type: RelRelatesTo})
				if templateID != "" {
					addRelation(result, relationSet, Relation{FromID: cveID, ToID: templateID, Type: RelHasTemplate})
				}
				if item.Classification.CPE != "" {
					cpeID := evidenceID("cpe", target, item.Classification.CPE)
					cpeEntity := Entity{
						ID: cpeID, Type: "cpe", Value: item.Classification.CPE,
						Source: "neutron", RawData: itemRaw,
						Confidence: 0.8, Status: "confirmed",
					}
					applyTarget(&cpeEntity, target)
					addEntity(result, entitySet, cpeEntity)
					addRelation(result, relationSet, Relation{FromID: cveID, ToID: cpeID, Type: RelHasCPE})
				}
				if cwe := strings.ToUpper(strings.TrimSpace(item.Classification.CWEID)); cwe != "" {
					cweID := evidenceID("cwe", target, cwe)
					cweEntity := Entity{
						ID: cweID, Type: "cwe", Value: cwe,
						Source: "neutron", RawData: itemRaw,
						Confidence: 0.8, Status: "confirmed",
					}
					applyTarget(&cweEntity, target)
					addEntity(result, entitySet, cweEntity)
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
