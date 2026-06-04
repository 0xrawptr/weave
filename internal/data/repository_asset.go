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
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "service", 100000, 0)
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
	targetID := generateID("target", scanTarget)
	return r.Postgres.CountAssetsFilteredByCampaign(ctx, targetID, assetType, source, status, campaignID)
}

// GetDiscoveredURLs returns HTTP URLs discovered by URL-expansion artifacts
// such as spray. These URLs can be fed back into planner iterations.
func (r *Repository) GetDiscoveredURLs(ctx context.Context, scanTarget string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "url", 100000, 0)
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		if a.Source == "spray" && isHTTPURL(a.Value) && plannerVisibleAssetStatus(a.Status) {
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
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "fingerprint", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var names []string
	for _, a := range assets {
		if plannerVisibleAssetStatus(a.Status) && !seen[a.Value] {
			seen[a.Value] = true
			names = append(names, a.Value)
		}
	}
	return names, nil
}

// GetTemplateIDs returns template IDs associated with fingerprints for a target.
// These are populated by the ETL enrichment phase.
func (r *Repository) GetTemplateIDs(ctx context.Context, scanTarget string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "template", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var ids []string
	for _, a := range assets {
		if plannerVisibleAssetStatus(a.Status) && !seen[a.Value] {
			seen[a.Value] = true
			ids = append(ids, a.Value)
		}
	}
	return ids, nil
}

// GetTags returns normalized enrichment tags associated with a target.
func (r *Repository) GetTags(ctx context.Context, scanTarget string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "tag", 10000, 0)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var tags []string
	for _, a := range assets {
		if plannerVisibleAssetStatus(a.Status) && !seen[a.Value] {
			seen[a.Value] = true
			tags = append(tags, a.Value)
		}
	}
	return tags, nil
}

// GetCVEAssets returns CVE candidate/confirmed assets for a target.
func (r *Repository) GetCVEAssets(ctx context.Context, scanTarget string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	targetID := generateID("target", scanTarget)
	assets, err := r.Postgres.QueryAssets(ctx, targetID, "cve", 10000, 0)
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		if plannerVisibleAssetStatus(asset.Status) {
			out = append(out, asset)
		}
	}
	return out, nil
}

// GetKnowledgeEvidence returns graph-derived planner evidence. Neo4j is the
// preferred source because it preserves relationships; Postgres is a fallback
// for local setups that only have normalized assets.
func (r *Repository) GetKnowledgeEvidence(ctx context.Context, scanTarget string) ([]EvidenceRecord, error) {
	targetID := generateID("target", scanTarget)
	if r.Neo4j != nil {
		evidence, err := r.Neo4j.QueryKnowledgeEvidence(ctx, targetID)
		if err == nil && len(evidence) > 0 {
			return dedupeEvidence(filterPlannerEvidence(evidence)), nil
		}
	}
	if r.Postgres == nil {
		return nil, nil
	}
	var evidence []EvidenceRecord
	for _, assetType := range []string{"product", "cve", "template", "intel", "cpe", "cwe"} {
		assets, err := r.Postgres.QueryAssets(ctx, targetID, assetType, 10000, 0)
		if err != nil {
			return nil, err
		}
		for _, asset := range assets {
			if !plannerVisibleAssetStatus(asset.Status) {
				continue
			}
			evidence = append(evidence, EvidenceRecord{
				Type:       asset.Type,
				Value:      asset.Value,
				Source:     asset.Source,
				Confidence: asset.Confidence,
				Severity:   asset.Severity,
				Priority:   asset.Priority,
				Status:     asset.Status,
				Path:       []EvidencePathStep{{Type: asset.Type, Value: asset.Value}},
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
