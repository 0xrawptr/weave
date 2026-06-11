package data

import (
	"context"
	"fmt"
	"strings"
)

const (
	AssetStatusObserved      = "observed"
	AssetStatusQueued        = "queued"
	AssetStatusNoise         = "noise"
	AssetStatusCandidate     = "candidate"
	AssetStatusConfirmed     = "confirmed"
	AssetStatusFalsePositive = "false_positive"
	AssetStatusIgnored       = "ignored"
	AssetStatusInteresting   = "interesting"
)

func (r *Repository) SaveAsset(ctx context.Context, asset *Asset) error {
	if r.Postgres != nil {
		if err := r.Postgres.InsertAsset(ctx, asset); err != nil {
			return err
		}
	}
	if r.Neo4j != nil {
		return r.Neo4j.CreateAssetNode(ctx, asset)
	}
	return nil
}

func (r *Repository) SaveEvidence(ctx context.Context, evidence *AssetEvidence) error {
	if r.Postgres != nil {
		if err := r.Postgres.InsertAssetEvidence(ctx, evidence); err != nil {
			return err
		}
	}
	if r.Neo4j != nil {
		return r.Neo4j.CreateAssetNode(ctx, &Asset{
			ID:          evidence.ID,
			CampaignID:  evidence.CampaignID,
			Type:        evidence.Type,
			Value:       evidence.Value,
			Source:      evidence.Source,
			TargetID:    evidence.TargetID,
			RawData:     evidence.RawData,
			Confidence:  evidence.Confidence,
			Severity:    evidence.Severity,
			Priority:    evidence.Priority,
			Status:      evidence.Status,
			SourceRunID: evidence.SourceRunID,
		})
	}
	return nil
}

func (r *Repository) SaveRelation(ctx context.Context, rel AssetRelation) error {
	if r.Neo4j == nil {
		return nil
	}
	return r.Neo4j.CreateRelation(ctx, rel)
}

func (r *Repository) UpdateAssetStatus(ctx context.Context, id, status string) error {
	if !ValidAssetStatus(status) {
		return fmt.Errorf("invalid asset status %q", status)
	}
	if r.Postgres != nil {
		if err := r.Postgres.UpdateAssetStatus(ctx, id, status); err != nil {
			return err
		}
	}
	if r.Neo4j != nil {
		return r.Neo4j.UpdateAssetStatus(ctx, id, status)
	}
	return nil
}

// GetWebURLs returns the web service URLs discovered by gogo for a scan target.
func (r *Repository) GetWebURLs(ctx context.Context, scanTarget string) ([]string, error) {
	return r.GetWebURLsInCampaign(ctx, scanTarget, "")
}

// GetWebURLsInCampaign returns web service URLs scoped to a campaign when provided.
func (r *Repository) GetWebURLsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	assets, err := r.Postgres.QueryAssetsFiltered(ctx, targetID, "service", campaignID, "", 100000, 0)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, a := range assets {
		if a.Source == "gogo" && plannerVisibleAssetStatus(a.Status) {
			urls = append(urls, a.Value)
		}
	}
	return urls, nil
}

func (r *Repository) CountAssets(ctx context.Context, scanTarget, assetType, source, status string) (int, error) {
	return r.CountAssetsInCampaign(ctx, scanTarget, "", assetType, source, status)
}

func (r *Repository) CountAssetsInCampaign(ctx context.Context, scanTarget, campaignID, assetType, source, status string) (int, error) {
	if r.Postgres == nil {
		return 0, nil
	}
	targetID := TargetID(scanTarget)
	return r.Postgres.CountAssetsFilteredByCampaign(ctx, targetID, assetType, source, status, campaignID)
}

// GetDiscoveredURLs returns HTTP URLs discovered by URL-expansion artifacts
// such as spray. These URLs can be fed back into planner iterations.
func (r *Repository) GetDiscoveredURLs(ctx context.Context, scanTarget string) ([]Asset, error) {
	return r.GetDiscoveredURLsInCampaign(ctx, scanTarget, "")
}

// GetDiscoveredURLsInCampaign returns spray-discovered URLs scoped to a campaign when provided.
func (r *Repository) GetDiscoveredURLsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	assets, err := r.Postgres.QueryAssetsFiltered(ctx, targetID, "url", campaignID, "", 100000, 0)
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		if a.Source == "spray" && isHTTPURL(a.Value) && plannerConsumableURLStatus(a.Status) {
			out = append(out, a)
		}
	}
	return out, nil
}

func plannerVisibleAssetStatus(status string) bool {
	switch status {
	case "", AssetStatusObserved, AssetStatusCandidate, AssetStatusConfirmed, AssetStatusInteresting:
		return true
	default:
		return false
	}
}

func plannerConsumableURLStatus(status string) bool {
	return plannerVisibleAssetStatus(status)
}

func ValidAssetStatus(status string) bool {
	switch status {
	case AssetStatusObserved,
		AssetStatusQueued,
		AssetStatusNoise,
		AssetStatusCandidate,
		AssetStatusConfirmed,
		AssetStatusFalsePositive,
		AssetStatusIgnored,
		AssetStatusInteresting:
		return true
	default:
		return false
	}
}

func isHTTPURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

// GetFingerprints returns the unique fingerprint names discovered by gogo for a target.
func (r *Repository) GetFingerprints(ctx context.Context, scanTarget string) ([]string, error) {
	return r.GetFingerprintsInCampaign(ctx, scanTarget, "")
}

func (r *Repository) GetFingerprintsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	values, err := r.Postgres.QueryAssetEvidence(ctx, targetID, "fingerprint", campaignID, "", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var names []string
	for _, value := range values {
		if plannerVisibleAssetStatus(value.Status) && !seen[value.Value] {
			seen[value.Value] = true
			names = append(names, value.Value)
		}
	}
	return names, nil
}

// GetTemplateIDs returns template IDs associated with fingerprints for a target.
// These are populated by the ETL enrichment phase.
func (r *Repository) GetTemplateIDs(ctx context.Context, scanTarget string) ([]string, error) {
	return r.GetTemplateIDsInCampaign(ctx, scanTarget, "")
}

func (r *Repository) GetTemplateIDsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	values, err := r.Postgres.QueryAssetEvidence(ctx, targetID, "template", campaignID, "", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var ids []string
	for _, value := range values {
		if plannerVisibleAssetStatus(value.Status) && !seen[value.Value] {
			seen[value.Value] = true
			ids = append(ids, value.Value)
		}
	}
	return ids, nil
}

// GetTags returns normalized enrichment tags associated with a target.
func (r *Repository) GetTags(ctx context.Context, scanTarget string) ([]string, error) {
	return r.GetTagsInCampaign(ctx, scanTarget, "")
}

func (r *Repository) GetTagsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	values, err := r.Postgres.QueryAssetEvidence(ctx, targetID, "tag", campaignID, "", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var tags []string
	for _, value := range values {
		if plannerVisibleAssetStatus(value.Status) && !seen[value.Value] {
			seen[value.Value] = true
			tags = append(tags, value.Value)
		}
	}
	return tags, nil
}

// GetCVEAssets returns CVE candidate/confirmed assets for a target.
func (r *Repository) GetCVEAssets(ctx context.Context, scanTarget string) ([]Asset, error) {
	return r.GetCVEAssetsInCampaign(ctx, scanTarget, "")
}

func (r *Repository) GetCVEAssetsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := TargetID(scanTarget)
	values, err := r.Postgres.QueryAssetEvidence(ctx, targetID, "cve", campaignID, "", 10000, 0)
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(values))
	for _, value := range values {
		if plannerVisibleAssetStatus(value.Status) {
			out = append(out, Asset{
				ID:         value.ID,
				CampaignID: value.CampaignID,
				Type:       value.Type,
				Value:      value.Value,
				Source:     value.Source,
				TargetID:   value.TargetID,
				RawData:    value.RawData,
				Confidence: value.Confidence,
				Severity:   value.Severity,
				Priority:   value.Priority,
				Status:     value.Status,
			})
		}
	}
	return out, nil
}

// GetKnowledgeEvidence returns graph-derived planner evidence. Neo4j is the
// preferred source because it preserves relationships; Postgres is a fallback
// for local setups that only have normalized assets.
func (r *Repository) GetKnowledgeEvidence(ctx context.Context, scanTarget string) ([]EvidenceRecord, error) {
	return r.GetKnowledgeEvidenceInCampaign(ctx, scanTarget, "")
}

func (r *Repository) GetKnowledgeEvidenceInCampaign(ctx context.Context, scanTarget, campaignID string) ([]EvidenceRecord, error) {
	targetID := TargetID(scanTarget)
	if r.Neo4j != nil {
		evidence, err := r.Neo4j.QueryKnowledgeEvidence(ctx, targetID, campaignID)
		if err == nil && len(evidence) > 0 {
			return dedupeEvidence(filterPlannerEvidence(evidence)), nil
		}
	}
	if r.Postgres == nil {
		return nil, nil
	}
	var evidence []EvidenceRecord
	for _, evidenceType := range []string{"fingerprint", "product", "version", "cve", "template", "intel", "cpe", "cwe", "tag"} {
		values, err := r.Postgres.QueryAssetEvidence(ctx, targetID, evidenceType, campaignID, "", 10000, 0)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			if !plannerVisibleAssetStatus(value.Status) {
				continue
			}
			evidence = append(evidence, EvidenceRecord{
				Type:       value.Type,
				Value:      value.Value,
				Source:     value.Source,
				Confidence: value.Confidence,
				Severity:   value.Severity,
				Priority:   value.Priority,
				Status:     value.Status,
				Path:       []EvidencePathStep{{Type: value.Type, Value: value.Value}},
			})
		}
	}
	return dedupeEvidence(evidence), nil
}

func filterPlannerEvidence(values []EvidenceRecord) []EvidenceRecord {
	out := make([]EvidenceRecord, 0, len(values))
	for _, value := range values {
		if plannerVisibleAssetStatus(value.Status) {
			out = append(out, value)
		}
	}
	return out
}

func dedupeEvidence(values []EvidenceRecord) []EvidenceRecord {
	seen := make(map[string]int, len(values))
	var out []EvidenceRecord
	for _, value := range values {
		if value.Type == "" || value.Value == "" {
			continue
		}
		key := value.Type + "|" + value.Value
		if i, ok := seen[key]; ok {
			if value.Priority > out[i].Priority ||
				(value.Priority == out[i].Priority && len(value.Path) > len(out[i].Path)) {
				out[i] = value
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, value)
	}
	return out
}
