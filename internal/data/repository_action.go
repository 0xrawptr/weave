package data

import (
	"context"
	"encoding/json"
)

func (r *Repository) ClaimAction(ctx context.Context, record ActionRecord) (bool, error) {
	if r.Postgres == nil {
		return true, nil
	}
	return r.Postgres.ClaimActionRecord(ctx, record)
}

func (r *Repository) CompleteAction(ctx context.Context, id string, success bool, errorMessage string) error {
	status := "completed"
	if !success {
		status = "failed"
	}
	return r.SetActionStatus(ctx, id, status, errorMessage)
}

func (r *Repository) SetActionStatus(ctx context.Context, id, status, errorMessage string) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.CompleteActionRecord(ctx, id, status, errorMessage)
}

func (r *Repository) GetActionRecordsFiltered(ctx context.Context, target, campaignID string) ([]ActionRecord, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryActionRecordsFiltered(ctx, target, campaignID)
}

func MarshalActionInput(input map[string]interface{}) []byte {
	raw, _ := json.Marshal(input)
	return raw
}
