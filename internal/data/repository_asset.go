package data

import (
	"context"
	"fmt"
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

// GetWebURLsInCampaign returns web service URLs scoped to a campaign when provided.
func (r *Repository) GetWebURLsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	assets, err := r.assetsInScope(ctx, scanTarget, campaignID, "service", "gogo", "")
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, a := range assets {
		if plannerVisibleAssetStatus(a.Status) {
			urls = append(urls, a.Value)
		}
	}
	return urls, nil
}

func (r *Repository) CountAssetsInCampaign(ctx context.Context, scanTarget, campaignID, assetType, source, status string) (int, error) {
	if r.Postgres == nil {
		return 0, nil
	}
	if plannerEvidenceType(assetType) {
		values, err := r.evidenceInScope(ctx, scanTarget, campaignID, assetType, source, status)
		if err != nil {
			return 0, err
		}
		return len(values), nil
	}
	assets, err := r.assetsInScope(ctx, scanTarget, campaignID, assetType, source, status)
	if err != nil {
		return 0, err
	}
	return len(assets), nil
}

func (r *Repository) CountAssetEventsInCampaign(ctx context.Context, scanTarget, campaignID, eventType, source string) (int, error) {
	events, err := r.GetAssetEventsInCampaign(ctx, scanTarget, campaignID, eventType, source, 100000, 0)
	if err != nil {
		return 0, err
	}
	return len(events), nil
}

func (r *Repository) GetAssetEventsInCampaign(ctx context.Context, scanTarget, campaignID, eventType, source string, limit, offset int) ([]AssetEvent, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 1000
	}
	events, err := r.Postgres.QueryAssetEvents(ctx, "", campaignID, eventType, 100000, 0)
	if err != nil {
		return nil, err
	}
	targetIDs := make([]string, 0, len(events))
	seenTargets := make(map[string]bool, len(events))
	for _, event := range events {
		if event.TargetID != "" && !seenTargets[event.TargetID] {
			seenTargets[event.TargetID] = true
			targetIDs = append(targetIDs, event.TargetID)
		}
	}
	targets, err := r.Postgres.GetTargetsByIDs(ctx, targetIDs)
	if err != nil {
		return nil, err
	}
	matches := NewScopeMatcher(scanTarget)
	out := make([]AssetEvent, 0, len(events))
	for _, event := range events {
		if source != "" && event.Source != source {
			continue
		}
		if scanTarget == "" {
			out = append(out, event)
			continue
		}
		target, ok := targets[event.TargetID]
		if !ok {
			continue
		}
		if matches(target.Value) {
			out = append(out, event)
		}
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(out) {
		return nil, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return append([]AssetEvent(nil), out[offset:end]...), nil
}

func plannerEvidenceType(value string) bool {
	switch value {
	case "fingerprint", "product", "version", "template", "tag", "cpe", "cve", "cwe", "intel", "extracted":
		return true
	default:
		return false
	}
}

// GetDiscoveredURLsInCampaign returns spray-discovered URLs scoped to a campaign when provided.
func (r *Repository) GetDiscoveredURLsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	assets, err := r.assetsInScope(ctx, scanTarget, campaignID, "url", "spray", "")
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		if IsHTTPURL(a.Value) && plannerVisibleAssetStatus(a.Status) {
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

func (r *Repository) GetFingerprintsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	values, err := r.evidenceInScope(ctx, scanTarget, campaignID, "fingerprint", "", "")
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

func (r *Repository) GetTemplateIDsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	values, err := r.evidenceInScope(ctx, scanTarget, campaignID, "template", "", "")
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

func (r *Repository) GetTagsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]string, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	values, err := r.evidenceInScope(ctx, scanTarget, campaignID, "tag", "", "")
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

func (r *Repository) GetCVEAssetsInCampaign(ctx context.Context, scanTarget, campaignID string) ([]Asset, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	values, err := r.evidenceInScope(ctx, scanTarget, campaignID, "cve", "", "")
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
				Status:     value.Status,
			})
		}
	}
	return out, nil
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
		values, err := r.evidenceInScope(ctx, scanTarget, campaignID, evidenceType, "", "")
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
				Status:     value.Status,
				Path:       []EvidencePathStep{{Type: value.Type, Value: value.Value}},
			})
		}
	}
	return dedupeEvidence(evidence), nil
}

func (r *Repository) assetsInScope(ctx context.Context, scanTarget, campaignID, assetType, source, status string) ([]Asset, error) {
	assets, err := r.Postgres.QueryAssetsFiltered(ctx, AssetQueryFilter{
		Type:       assetType,
		CampaignID: campaignID,
		Status:     status,
	}, 100000, 0)
	if err != nil {
		return nil, err
	}
	matches := NewScopeMatcher(scanTarget)
	out := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		if source != "" && asset.Source != source {
			continue
		}
		if matches(asset.Value) {
			out = append(out, asset)
		}
	}
	return out, nil
}

func (r *Repository) evidenceInScope(ctx context.Context, scanTarget, campaignID, evidenceType, source, status string) ([]AssetEvidence, error) {
	values, err := r.Postgres.QueryAssetEvidence(ctx, "", evidenceType, campaignID, status, 100000, 0)
	if err != nil {
		return nil, err
	}
	targetIDs := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if source != "" && value.Source != source {
			continue
		}
		if value.TargetID != "" && !seen[value.TargetID] {
			seen[value.TargetID] = true
			targetIDs = append(targetIDs, value.TargetID)
		}
	}
	targets, err := r.Postgres.GetTargetsByIDs(ctx, targetIDs)
	if err != nil {
		return nil, err
	}
	matches := NewScopeMatcher(scanTarget)
	out := make([]AssetEvidence, 0, len(values))
	for _, value := range values {
		if source != "" && value.Source != source {
			continue
		}
		target, ok := targets[value.TargetID]
		if !ok {
			continue
		}
		if matches(target.Value) {
			out = append(out, value)
		}
	}
	return out, nil
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
			if SeverityRank(value.Severity) > SeverityRank(out[i].Severity) ||
				(SeverityRank(value.Severity) == SeverityRank(out[i].Severity) && len(value.Path) > len(out[i].Path)) {
				out[i] = value
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, value)
	}
	return out
}
