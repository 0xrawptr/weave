package data

import (
	"context"
)

// SaveRawEvent stores an artifact's output untouched before transformation.
func (r *Repository) SaveRawEvent(ctx context.Context, e *RawEvent) error {
	if r.Postgres == nil {
		return nil
	}
	targetType := e.TargetType
	if targetType == "" {
		targetType = "unknown"
	}
	targetID := generateID("target", e.TargetID)
	_ = r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: targetType, Value: e.TargetID})
	return r.Postgres.InsertRawEvent(ctx, e)
}
