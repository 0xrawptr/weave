package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type NucleiExtractor struct{}

func (n *NucleiExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type nucleiItem struct {
		TemplateID    string                 `json:"template_id"`
		TemplatePath  string                 `json:"template_path,omitempty"`
		TemplateURL   string                 `json:"template_url,omitempty"`
		Info          string                 `json:"info"`
		Severity      string                 `json:"severity"`
		Tags          []string               `json:"tags,omitempty"`
		Target        string                 `json:"target"`
		Matched       string                 `json:"matched"`
		Type          string                 `json:"type,omitempty"`
		MatcherName   string                 `json:"matcher_name,omitempty"`
		ExtractorName string                 `json:"extractor_name,omitempty"`
		Host          string                 `json:"host,omitempty"`
		IP            string                 `json:"ip,omitempty"`
		Port          string                 `json:"port,omitempty"`
		Scheme        string                 `json:"scheme,omitempty"`
		URL           string                 `json:"url,omitempty"`
		Path          string                 `json:"path,omitempty"`
		CVEs          []string               `json:"cves,omitempty"`
		CWEs          []string               `json:"cwes,omitempty"`
		CPE           string                 `json:"cpe,omitempty"`
		CVSSScore     float64                `json:"cvss_score,omitempty"`
		EPSSScore     float64                `json:"epss_score,omitempty"`
		Metadata      map[string]interface{} `json:"metadata,omitempty"`
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
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Results {
		if !acceptNucleiETLItem(item.TemplateID, item.Info) {
			continue
		}
		itemRaw, _ := json.Marshal(item)
		urlValue := firstNonEmpty(item.URL, item.Target, item.Matched)
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
				Source: "nuclei", RawData: itemRaw,
				Confidence: 1.0, Status: "observed", Quality: urlQuality,
			}
			applyTarget(&urlEntity, target)
			addEntity(result, entitySet, urlEntity)
		}

		templateID := evidenceID("template", target, item.TemplateID)
		if item.TemplateID != "" {
			templateEntity := Entity{
				ID: templateID, Type: "template", Value: item.TemplateID,
				Source: "nuclei", RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Status: nucleiFindingStatus(item.Severity), Tags: item.Tags,
			}
			applyTarget(&templateEntity, target)
			addEntity(result, entitySet, templateEntity)
		}

		vulnID := ""
		if nucleiIsVulnerability(item.Severity, item.TemplateID, item.CVEs) {
			vulnID = evidenceID("vuln", target, urlValue, item.TemplateID)
			vulnEntity := Entity{
				ID: vulnID, Type: "vulnerability",
				Value:  fmt.Sprintf("%s: %s", strings.ToLower(item.Severity), item.Info),
				Source: "nuclei", RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Status: "confirmed",
			}
			applyTarget(&vulnEntity, target)
			addEntity(result, entitySet, vulnEntity)
			if urlID != "" {
				addRelation(result, relationSet, Relation{
					FromID: urlID, ToID: vulnID, Type: RelHasVulnerability,
				})
			}
			if item.TemplateID != "" {
				addRelation(result, relationSet, Relation{
					FromID: templateID, ToID: vulnID, Type: RelDetects,
				})
			}
		}
		for _, cve := range nucleiCVEs(item.TemplateID, item.CVEs) {
			cveID := evidenceID("cve", target, cve)
			cveEntity := Entity{
				ID: cveID, Type: "cve", Value: cve,
				Source: "nuclei", RawData: itemRaw,
				Confidence: 1.0, Severity: strings.ToLower(item.Severity),
				Status: "confirmed",
			}
			applyTarget(&cveEntity, target)
			addEntity(result, entitySet, cveEntity)
			if vulnID != "" {
				addRelation(result, relationSet, Relation{FromID: vulnID, ToID: cveID, Type: RelRelatesTo})
			}
			if item.TemplateID != "" {
				addRelation(result, relationSet, Relation{FromID: cveID, ToID: templateID, Type: RelHasTemplate})
			}
			if item.CPE != "" {
				cpeID := evidenceID("cpe", target, item.CPE)
				cpeEntity := Entity{
					ID: cpeID, Type: "cpe", Value: item.CPE,
					Source: "nuclei", RawData: itemRaw,
					Confidence: 0.8, Status: "confirmed",
				}
				applyTarget(&cpeEntity, target)
				addEntity(result, entitySet, cpeEntity)
				addRelation(result, relationSet, Relation{FromID: cveID, ToID: cpeID, Type: RelHasCPE})
			}
			for _, cwe := range item.CWEs {
				cwe = strings.ToUpper(strings.TrimSpace(cwe))
				if cwe == "" {
					continue
				}
				cweID := evidenceID("cwe", target, cwe)
				cweEntity := Entity{
					ID: cweID, Type: "cwe", Value: cwe,
					Source: "nuclei", RawData: itemRaw,
					Confidence: 0.8, Status: "confirmed",
				}
				applyTarget(&cweEntity, target)
				addEntity(result, entitySet, cweEntity)
				addRelation(result, relationSet, Relation{FromID: cveID, ToID: cweID, Type: RelHasCWE})
			}
		}
	}
	return result, nil
}

func acceptNucleiETLItem(templateID, info string) bool {
	templateID = strings.TrimSpace(templateID)
	if templateID == "" || strings.HasPrefix(templateID, "cluster-") {
		return false
	}
	return strings.TrimSpace(info) != ""
}

func nucleiFindingStatus(severity string) string {
	if nucleiIsActionableSeverity(severity) {
		return "confirmed"
	}
	return "observed"
}

func nucleiIsVulnerability(severity, templateID string, cves []string) bool {
	return nucleiIsActionableSeverity(severity) || len(nucleiCVEs(templateID, cves)) > 0
}

func nucleiIsActionableSeverity(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
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

func nucleiCVEs(templateID string, cves []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, cve := range cves {
		cve = strings.ToUpper(strings.TrimSpace(cve))
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		out = append(out, cve)
	}
	if cve := templateCVE(templateID); cve != "" && !seen[cve] {
		out = append(out, cve)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
