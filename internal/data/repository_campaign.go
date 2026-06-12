package data

import (
	"context"
	"fmt"
	"strings"
)

const (
	CampaignStatusActive    = "active"
	CampaignStatusPaused    = "paused"
	CampaignStatusCompleted = "completed"
	CampaignStatusArchived  = "archived"

	CampaignPhaseAuto         = "auto"
	CampaignPhaseBootstrap    = "bootstrap"
	CampaignPhaseDiscovery    = "discovery"
	CampaignPhaseExpansion    = "expansion"
	CampaignPhaseVerification = "verification"
	CampaignPhaseSteady       = "steady"
)

func (r *Repository) UpsertCampaign(ctx context.Context, campaign Campaign) error {
	if !ValidCampaignStatus(defaultString(campaign.Status, CampaignStatusActive)) {
		return fmt.Errorf("invalid campaign status %q", campaign.Status)
	}
	campaign.Phase = NormalizeCampaignPhase(defaultString(campaign.Phase, CampaignPhaseBootstrap))
	if campaign.Phase == CampaignPhaseAuto {
		campaign.Phase = CampaignPhaseBootstrap
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

func (r *Repository) UpdateCampaignPhase(ctx context.Context, campaignID, batchID, phase, reason string) (*Campaign, error) {
	phase = NormalizeCampaignPhase(phase)
	if phase == CampaignPhaseAuto {
		return nil, fmt.Errorf("invalid campaign phase %q", phase)
	}
	if r.Postgres == nil {
		return &Campaign{ID: campaignID, Phase: phase, PhaseReason: reason}, nil
	}
	return r.Postgres.UpdateCampaignPhase(ctx, campaignID, batchID, phase, reason)
}

func (r *Repository) GetCampaignPhaseEvents(ctx context.Context, campaignID string, limit, offset int) ([]CampaignPhaseEvent, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryCampaignPhaseEvents(ctx, campaignID, limit, offset)
}

func ValidCampaignStatus(status string) bool {
	switch status {
	case CampaignStatusActive, CampaignStatusPaused, CampaignStatusCompleted, CampaignStatusArchived:
		return true
	default:
		return false
	}
}

func NormalizeCampaignPhase(phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case CampaignPhaseBootstrap, CampaignPhaseDiscovery, CampaignPhaseExpansion, CampaignPhaseVerification, CampaignPhaseSteady:
		return strings.ToLower(strings.TrimSpace(phase))
	default:
		return CampaignPhaseAuto
	}
}

func ValidCampaignPhase(phase string) bool {
	return NormalizeCampaignPhase(phase) != CampaignPhaseAuto
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
