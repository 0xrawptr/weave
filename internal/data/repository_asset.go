package data

import (
	"context"
	"strings"
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
		if a.Source == "gogo" {
			urls = append(urls, a.Value)
		}
	}
	return urls, nil
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
		if a.Source == "spray" && isHTTPURL(a.Value) {
			out = append(out, a)
		}
	}
	return out, nil
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
		if !seen[a.Value] {
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
		if !seen[a.Value] {
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
		if !seen[a.Value] {
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
	return r.Postgres.QueryAssets(ctx, targetID, "cve", 10000, 0)
}

// GetKnowledgeEvidence returns graph-derived planner evidence. Neo4j is the
// preferred source because it preserves relationships; Postgres is a fallback
// for local setups that only have normalized assets.
func (r *Repository) GetKnowledgeEvidence(ctx context.Context, scanTarget string) ([]EvidenceRecord, error) {
	targetID := generateID("target", scanTarget)
	if r.Neo4j != nil {
		evidence, err := r.Neo4j.QueryKnowledgeEvidence(ctx, targetID)
		if err == nil && len(evidence) > 0 {
			return dedupeEvidence(evidence), nil
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
