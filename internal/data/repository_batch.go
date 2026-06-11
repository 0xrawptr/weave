package data

import "context"

func (r *Repository) UpsertBatchRun(ctx context.Context, run BatchRun) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpsertBatchRun(ctx, run)
}

func (r *Repository) UpsertBatchChunk(ctx context.Context, chunk BatchChunk) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpsertBatchChunk(ctx, chunk)
}

func (r *Repository) GetBatchRuns(ctx context.Context, status string, limit, offset int) ([]BatchRun, error) {
	return r.GetBatchRunsFiltered(ctx, status, "", limit, offset)
}

func (r *Repository) GetBatchRunsFiltered(ctx context.Context, status, campaignID string, limit, offset int) ([]BatchRun, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryBatchRunsFiltered(ctx, status, campaignID, limit, offset)
}

func (r *Repository) GetBatchRun(ctx context.Context, batchID string) (*BatchRun, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.GetBatchRun(ctx, batchID)
}

func (r *Repository) GetBatchChunks(ctx context.Context, batchID, status string, limit, offset int) ([]BatchChunk, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryBatchChunks(ctx, batchID, status, limit, offset)
}
