package data

import "context"

func (r *Repository) CreatePolicy(ctx context.Context, policy Policy) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.CreatePolicy(ctx, policy)
}

func (r *Repository) ListPolicies(ctx context.Context, limit, offset int) ([]Policy, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.ListPolicies(ctx, limit, offset)
}

func (r *Repository) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	if r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.GetPolicy(ctx, id)
}

func (r *Repository) UpdatePolicy(ctx context.Context, policy Policy) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpdatePolicy(ctx, policy)
}

func (r *Repository) DeletePolicy(ctx context.Context, id string) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.DeletePolicy(ctx, id)
}
