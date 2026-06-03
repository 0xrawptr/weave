package etl

import (
	"context"
	"fmt"

	"github.com/0xrawptr/weave/internal/data"
)

func MakeLoader(repo *data.Repository) Loader {
	return &dbLoader{repo: repo}
}

type dbLoader struct {
	repo *data.Repository
}

func (l *dbLoader) Save(ctx context.Context, r *ExtractResult) error {
	for _, e := range r.Entities {
		asset := &data.Asset{
			ID:       e.ID,
			Type:     e.Type,
			Value:    e.Value,
			Source:   e.Source,
			TargetID: e.TargetID,
			RawData:  e.RawData,
		}
		if err := l.repo.SaveAsset(ctx, asset); err != nil {
			return fmt.Errorf("save asset %s: %w", e.ID, err)
		}
	}
	for _, rel := range r.Relations {
		if err := l.repo.SaveRelation(ctx, data.AssetRelation{
			FromAssetID: rel.FromID,
			ToAssetID:   rel.ToID,
			Type:        rel.Type,
		}); err != nil {
			return fmt.Errorf("save relation %s: %w", rel.Type, err)
		}
	}
	return nil
}
