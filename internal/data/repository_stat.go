package data

import "context"

func (r *Repository) SaveArtifactStat(ctx context.Context, stat ArtifactStat) error {
	if r == nil || r.Postgres == nil {
		return nil
	}
	return r.Postgres.InsertArtifactStat(ctx, stat)
}

func (r *Repository) GetArtifactStats(ctx context.Context, campaignID, workflowID, artifactName, target string, limit, offset int) ([]ArtifactStat, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryArtifactStats(ctx, campaignID, workflowID, artifactName, target, limit, offset)
}
