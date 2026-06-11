package data

import (
	"context"
)

// SaveRawEvent stores an artifact's output untouched before transformation.
func (r *Repository) SaveRawEvent(ctx context.Context, e *RawEvent) error {
	if r.Postgres == nil {
		return nil
	}
	targetValue := e.TargetValue
	if targetValue == "" {
		targetValue = e.TargetID
	}
	targetType := e.TargetType
	if targetType == "" {
		targetType = "unknown"
	}
	targetID := TargetID(targetValue)
	e.TargetID = targetID
	e.TargetValue = targetValue
	_ = r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: targetType, Value: targetValue})
	return r.Postgres.InsertRawEvent(ctx, e)
}
