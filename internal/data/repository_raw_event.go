package data

import (
	"context"
	"encoding/json"
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

// PersistSingleResult persists a single gogo result directly (streaming mode).
func (r *Repository) PersistSingleResult(ctx context.Context, scanTarget string, resultJSON []byte) error {
	if resultJSON == nil {
		return nil
	}
	wrapped, _ := json.Marshal(map[string]interface{}{
		"results": []json.RawMessage{resultJSON},
	})
	return r.persistGogoResult(ctx, scanTarget, wrapped)
}
