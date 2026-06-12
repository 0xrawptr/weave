package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

func MakeLoader(repo *data.Repository) Loader {
	return &dbLoader{repo: repo}
}

type dbLoader struct {
	repo *data.Repository
}

func (l *dbLoader) Save(ctx context.Context, r *ExtractResult) error {
	campaignID := CampaignIDFromContext(ctx)
	for _, e := range r.Entities {
		status := defaultStatus(e.Status, "observed")
		if err := l.ensureEntityTarget(ctx, &e); err != nil {
			return err
		}
		if evidenceOnlyType(e.Type) {
			if err := l.saveEvidenceEntity(ctx, e, ""); err != nil {
				return err
			}
		} else {
			asset := &data.Asset{
				ID:          e.ID,
				CampaignID:  campaignID,
				Type:        e.Type,
				Value:       e.Value,
				Source:      e.Source,
				TargetID:    e.TargetID,
				RawData:     entityRawData(e),
				Confidence:  e.Confidence,
				Severity:    e.Severity,
				Status:      status,
				SourceRunID: e.SourceRunID,
			}
			if err := l.repo.SaveAsset(ctx, asset); err != nil {
				return fmt.Errorf("save asset %s: %w", e.ID, err)
			}
		}
		if status == data.AssetStatusNoise {
			continue
		}

		productID, err := l.saveProductContext(ctx, e)
		if err != nil {
			return err
		}

		// Persist enriched template IDs as template assets.
		for _, tid := range e.TemplateIDs {
			tplID := data.GenerateID("template", e.TargetID, tid)
			tplAsset := &data.AssetEvidence{
				ID:         tplID,
				CampaignID: campaignID,
				Type:       "template",
				Value:      tid,
				Source:     e.Source,
				TargetID:   e.TargetID,
				Confidence: 0.6,
				Status:     "candidate",
			}
			if err := l.repo.SaveEvidence(ctx, tplAsset); err != nil {
				return fmt.Errorf("save template %s: %w", tid, err)
			}
			if productID != "" {
				if err := l.repo.SaveRelation(ctx, data.AssetRelation{
					FromAssetID: productID, ToAssetID: tplID, Type: RelHasTemplate,
				}); err != nil {
					return fmt.Errorf("save product template relation %s: %w", tid, err)
				}
			}
		}

		// Persist enrichment tags separately so nuclei can use normalized tags
		// instead of only raw fingerprint names.
		for _, tag := range e.Tags {
			tagID := data.GenerateID("tag", e.TargetID, tag)
			tagAsset := &data.AssetEvidence{
				ID:         tagID,
				CampaignID: campaignID,
				Type:       "tag",
				Value:      tag,
				Source:     e.Source,
				TargetID:   e.TargetID,
				Confidence: 0.5,
				Status:     "candidate",
			}
			if err := l.repo.SaveEvidence(ctx, tagAsset); err != nil {
				return fmt.Errorf("save tag %s: %w", tag, err)
			}
			if err := l.repo.SaveRelation(ctx, data.AssetRelation{
				FromAssetID: e.ID, ToAssetID: tagID, Type: RelRelatesTo,
			}); err != nil {
				return fmt.Errorf("save tag relation %s: %w", tag, err)
			}
		}

		for _, cpe := range e.CPEs {
			cpeID := data.GenerateID("cpe", e.TargetID, cpe)
			cpeAsset := &data.AssetEvidence{
				ID:         cpeID,
				CampaignID: campaignID,
				Type:       "cpe",
				Value:      cpe,
				Source:     e.Source,
				TargetID:   e.TargetID,
				Confidence: 0.5,
				Status:     "candidate",
			}
			if err := l.repo.SaveEvidence(ctx, cpeAsset); err != nil {
				return fmt.Errorf("save cpe %s: %w", cpe, err)
			}
			if productID != "" {
				if err := l.repo.SaveRelation(ctx, data.AssetRelation{
					FromAssetID: productID, ToAssetID: cpeID, Type: RelHasCPE,
				}); err != nil {
					return fmt.Errorf("save product cpe relation %s: %w", cpe, err)
				}
			}
		}

		// Persist candidate CVEs as first-class graph nodes. These are not
		// confirmed vulnerabilities; they represent pre-scan hypotheses.
		cveIntel := make(map[string]CVEInfo, len(e.CVEIntel))
		for _, intel := range e.CVEIntel {
			if intel.ID != "" {
				cveIntel[intel.ID] = intel
			}
		}
		for _, cve := range e.CVEs {
			cveID := data.GenerateID("cve", e.TargetID, cve)
			var raw []byte
			var intel CVEInfo
			if value, ok := cveIntel[cve]; ok {
				intel = value
				raw, _ = json.Marshal(intel)
			}
			cveAsset := &data.AssetEvidence{
				ID:         cveID,
				CampaignID: campaignID,
				Type:       "cve",
				Value:      cve,
				Source:     e.Source,
				TargetID:   e.TargetID,
				RawData:    raw,
				Confidence: 0.5,
				Severity:   highestSeverity(e.CVEIntel, cve),
				Status:     "candidate",
			}
			if err := l.repo.SaveEvidence(ctx, cveAsset); err != nil {
				return fmt.Errorf("save cve %s: %w", cve, err)
			}
			if productID != "" {
				if err := l.repo.SaveRelation(ctx, data.AssetRelation{
					FromAssetID: productID, ToAssetID: cveID, Type: RelAffectedBy,
				}); err != nil {
					return fmt.Errorf("save affected_by relation %s: %w", cve, err)
				}
			}
			if err := l.saveCVEKnowledge(ctx, e, cveID, intel); err != nil {
				return err
			}
			for _, tid := range e.TemplateIDs {
				if !templateMatchesCVE(tid, cve) {
					continue
				}
				tplID := data.GenerateID("template", e.TargetID, tid)
				if err := l.repo.SaveRelation(ctx, data.AssetRelation{
					FromAssetID: cveID, ToAssetID: tplID, Type: RelHasTemplate,
				}); err != nil {
					return fmt.Errorf("save cve template relation %s -> %s: %w", cve, tid, err)
				}
			}
		}
	}

	for _, rel := range r.Relations {
		if err := l.repo.SaveRelation(ctx, data.AssetRelation{
			FromAssetID: rel.FromID,
			ToAssetID:   rel.ToID,
			Type:        rel.Type,
		}); err != nil {
			return fmt.Errorf("save relation %s: %w", rel.Type, err)
		}
	}
	return nil
}

func (l *dbLoader) ensureEntityTarget(ctx context.Context, e *Entity) error {
	if e.TargetID == "" {
		target := targetForValue(e.Value)
		applyTarget(e, target)
	}
	targetValue := e.TargetValue
	if targetValue == "" {
		targetValue = e.Value
	}
	targetType := e.TargetType
	if targetType == "" {
		targetType = inferTargetType(targetValue)
	}
	if l.repo == nil || l.repo.Postgres == nil || e.TargetID == "" || targetValue == "" {
		return nil
	}
	return l.repo.EnsureTarget(ctx, &data.Target{ID: e.TargetID, Type: targetType, Value: targetValue})
}

func entityRawData(e Entity) []byte {
	if e.Quality == nil {
		return e.RawData
	}
	var raw map[string]interface{}
	if len(e.RawData) > 0 && json.Unmarshal(e.RawData, &raw) == nil {
		raw["_quality"] = e.Quality
		out, _ := json.Marshal(raw)
		return out
	}
	out, _ := json.Marshal(map[string]interface{}{
		"value":    e.Value,
		"raw":      json.RawMessage(e.RawData),
		"_quality": e.Quality,
	})
	return out
}

func (l *dbLoader) saveEvidenceEntity(ctx context.Context, e Entity, subjectID string) error {
	status := defaultStatus(e.Status, "observed")
	evidence := &data.AssetEvidence{
		ID:          e.ID,
		CampaignID:  CampaignIDFromContext(ctx),
		TargetID:    e.TargetID,
		SubjectID:   subjectID,
		Type:        e.Type,
		Value:       e.Value,
		Source:      e.Source,
		RawData:     entityRawData(e),
		Confidence:  e.Confidence,
		Severity:    e.Severity,
		Status:      status,
		Reason:      e.Reason,
		SourceRunID: e.SourceRunID,
	}
	if err := l.repo.SaveEvidence(ctx, evidence); err != nil {
		return fmt.Errorf("save evidence %s: %w", e.ID, err)
	}
	return nil
}

func evidenceOnlyType(entityType string) bool {
	switch entityType {
	case "fingerprint", "product", "version", "template", "tag", "cpe", "cve", "cwe", "intel", "extracted":
		return true
	default:
		return false
	}
}

func (l *dbLoader) saveProductContext(ctx context.Context, e Entity) (string, error) {
	if e.Product == "" && e.Version == "" && !needsSyntheticProduct(e) {
		return "", nil
	}
	productValue := e.Product
	if productValue == "" {
		productValue = e.Value
	}
	if productValue == "" {
		return "", nil
	}
	productID := data.GenerateID("product", e.TargetID, productValue)
	product := &data.AssetEvidence{
		ID:         productID,
		CampaignID: CampaignIDFromContext(ctx),
		Type:       "product",
		Value:      productValue,
		Source:     e.Source,
		TargetID:   e.TargetID,
		Confidence: e.Confidence,
		Status:     defaultStatus(e.Status, "observed"),
	}
	if err := l.repo.SaveEvidence(ctx, product); err != nil {
		return "", fmt.Errorf("save product %s: %w", productValue, err)
	}
	if err := l.repo.SaveRelation(ctx, data.AssetRelation{
		FromAssetID: e.ID, ToAssetID: productID, Type: RelIdentifiesProduct,
	}); err != nil {
		return "", fmt.Errorf("save product relation %s: %w", productValue, err)
	}
	if e.Version == "" {
		return productID, nil
	}
	versionID := data.GenerateID("version", e.TargetID, productValue, e.Version)
	version := &data.AssetEvidence{
		ID:         versionID,
		CampaignID: CampaignIDFromContext(ctx),
		Type:       "version",
		Value:      e.Version,
		Source:     e.Source,
		TargetID:   e.TargetID,
		Confidence: e.Confidence,
		Status:     defaultStatus(e.Status, "observed"),
	}
	if err := l.repo.SaveEvidence(ctx, version); err != nil {
		return "", fmt.Errorf("save version %s: %w", e.Version, err)
	}
	if err := l.repo.SaveRelation(ctx, data.AssetRelation{
		FromAssetID: productID, ToAssetID: versionID, Type: RelHasVersion,
	}); err != nil {
		return "", fmt.Errorf("save version relation %s: %w", e.Version, err)
	}
	return productID, nil
}

func (l *dbLoader) saveCVEKnowledge(ctx context.Context, e Entity, cveID string, intel CVEInfo) error {
	if err := l.saveCVEIntel(ctx, e, cveID, intel); err != nil {
		return err
	}

	productValue := intel.Product
	if productValue == "" {
		productValue = intel.VendorProject
	}
	if productValue != "" {
		productID := data.GenerateID("product", e.TargetID, productValue)
		product := &data.AssetEvidence{
			ID:         productID,
			CampaignID: CampaignIDFromContext(ctx),
			Type:       "product",
			Value:      productValue,
			Source:     e.Source,
			TargetID:   e.TargetID,
			Confidence: 0.5,
			Status:     "candidate",
		}
		if err := l.repo.SaveEvidence(ctx, product); err != nil {
			return fmt.Errorf("save cve product %s: %w", productValue, err)
		}
		if err := l.repo.SaveRelation(ctx, data.AssetRelation{
			FromAssetID: productID, ToAssetID: cveID, Type: RelAffectedBy,
		}); err != nil {
			return fmt.Errorf("save affected_by relation %s: %w", productValue, err)
		}
	}

	for _, cpe := range intel.CPEs {
		cpeID := data.GenerateID("cpe", e.TargetID, cpe)
		cpeAsset := &data.AssetEvidence{
			ID:         cpeID,
			CampaignID: CampaignIDFromContext(ctx),
			Type:       "cpe",
			Value:      cpe,
			Source:     e.Source,
			TargetID:   e.TargetID,
			Confidence: 0.5,
			Status:     "candidate",
		}
		if err := l.repo.SaveEvidence(ctx, cpeAsset); err != nil {
			return fmt.Errorf("save cpe %s: %w", cpe, err)
		}
		if err := l.repo.SaveRelation(ctx, data.AssetRelation{
			FromAssetID: cveID, ToAssetID: cpeID, Type: RelHasCPE,
		}); err != nil {
			return fmt.Errorf("save cpe relation %s: %w", cpe, err)
		}
	}
	for _, cwe := range intel.CWEs {
		cweID := data.GenerateID("cwe", e.TargetID, cwe)
		cweAsset := &data.AssetEvidence{
			ID:         cweID,
			CampaignID: CampaignIDFromContext(ctx),
			Type:       "cwe",
			Value:      cwe,
			Source:     e.Source,
			TargetID:   e.TargetID,
			Confidence: 0.5,
			Status:     "candidate",
		}
		if err := l.repo.SaveEvidence(ctx, cweAsset); err != nil {
			return fmt.Errorf("save cwe %s: %w", cwe, err)
		}
		if err := l.repo.SaveRelation(ctx, data.AssetRelation{
			FromAssetID: cveID, ToAssetID: cweID, Type: RelHasCWE,
		}); err != nil {
			return fmt.Errorf("save cwe relation %s: %w", cwe, err)
		}
	}
	return nil
}

func needsSyntheticProduct(e Entity) bool {
	if e.Type != "fingerprint" {
		return false
	}
	return len(e.TemplateIDs) > 0 || len(e.CVEs) > 0 || len(e.CPEs) > 0 || len(e.CVEIntel) > 0
}

func templateMatchesCVE(templateID, cve string) bool {
	if templateID == "" || cve == "" {
		return false
	}
	return strings.EqualFold(templateID, cve) || strings.Contains(strings.ToLower(templateID), strings.ToLower(cve))
}

func (l *dbLoader) saveCVEIntel(ctx context.Context, e Entity, cveID string, intel CVEInfo) error {
	if intel.ID == "" || !hasIntelEvidence(intel) {
		return nil
	}
	raw, _ := json.Marshal(intel)
	intelID := data.GenerateID("intel", e.TargetID, intel.ID)
	intelAsset := &data.AssetEvidence{
		ID:         intelID,
		CampaignID: CampaignIDFromContext(ctx),
		Type:       "intel",
		Value:      intelSummary(intel),
		Source:     e.Source,
		TargetID:   e.TargetID,
		RawData:    raw,
		Confidence: 0.8,
		Severity:   intel.CVSSSeverity,
		Status:     "candidate",
	}
	if err := l.repo.SaveEvidence(ctx, intelAsset); err != nil {
		return fmt.Errorf("save cve intel %s: %w", intel.ID, err)
	}
	if err := l.repo.SaveRelation(ctx, data.AssetRelation{
		FromAssetID: cveID, ToAssetID: intelID, Type: RelHasIntel,
	}); err != nil {
		return fmt.Errorf("save cve intel relation %s: %w", intel.ID, err)
	}
	return nil
}

func hasIntelEvidence(intel CVEInfo) bool {
	return intel.KEV || intel.EPSS != 0 || intel.EPSSPercentile != 0 ||
		intel.CVSSScore != 0 || len(intel.SSVC) > 0 || intel.VulnerabilityName != ""
}

func intelSummary(intel CVEInfo) string {
	parts := []string{intel.ID}
	if intel.KEV {
		parts = append(parts, "KEV")
	}
	if intel.EPSSPercentile != 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", intel.EPSSPercentile))
	}
	if intel.CVSSScore != 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", intel.CVSSScore))
	}
	return strings.Join(parts, " ")
}

func defaultStatus(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func highestSeverity(intel []CVEInfo, cve string) string {
	for _, item := range intel {
		if item.ID == cve {
			return item.CVSSSeverity
		}
	}
	return ""
}
