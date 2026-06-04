package data

import (
	"context"
	"fmt"
)

const (
	CampaignStatusActive    = "active"
	CampaignStatusPaused    = "paused"
	CampaignStatusCompleted = "completed"
	CampaignStatusArchived  = "archived"
)

func (r *Repository) UpsertCampaign(ctx context.Context, campaign Campaign) error {
	if !ValidCampaignStatus(defaultString(campaign.Status, CampaignStatusActive)) {
		return fmt.Errorf("invalid campaign status %q", campaign.Status)
	}
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpsertCampaign(ctx, campaign)
}

func (r *Repository) GetCampaign(ctx context.Context, id string) (*Campaign, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.GetCampaign(ctx, id)
}

func (r *Repository) GetCampaigns(ctx context.Context, status string, limit, offset int) ([]Campaign, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryCampaigns(ctx, status, limit, offset)
}

func (r *Repository) UpdateCampaignStatus(ctx context.Context, id, status string) error {
	if !ValidCampaignStatus(status) {
		return fmt.Errorf("invalid campaign status %q", status)
	}
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpdateCampaignStatus(ctx, id, status)
}

func ValidCampaignStatus(status string) bool {
	switch status {
	case CampaignStatusActive, CampaignStatusPaused, CampaignStatusCompleted, CampaignStatusArchived:
		return true
	default:
		return false
	}
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
