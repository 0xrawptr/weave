package data

import "context"

func (r *Repository) UpsertWorkItem(ctx context.Context, item WorkItem) error {
	if r == nil || r.Postgres == nil {
		return nil
	}
	return r.Postgres.UpsertWorkItem(ctx, item)
}

func (r *Repository) UpsertWorkItems(ctx context.Context, items []WorkItem) error {
	if r == nil || r.Postgres == nil || len(items) == 0 {
		return nil
	}
	return r.Postgres.UpsertWorkItems(ctx, items)
}

func (r *Repository) ClaimWorkItem(ctx context.Context, request WorkItemClaimRequest) (*WorkItem, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.ClaimWorkItem(ctx, request)
}

func (r *Repository) SetWorkItemStatus(ctx context.Context, id, status, workflowID, errorMessage string, incrementAttempt bool) error {
	return r.SetWorkItemStatusWithLease(ctx, id, status, workflowID, errorMessage, incrementAttempt, 0)
}

func (r *Repository) SetWorkItemStatusWithLease(ctx context.Context, id, status, workflowID, errorMessage string, incrementAttempt bool, leaseSeconds int) error {
	if r == nil || r.Postgres == nil {
		return nil
	}
	return r.Postgres.SetWorkItemStatus(ctx, id, status, workflowID, errorMessage, incrementAttempt, leaseSeconds)
}

func (r *Repository) HeartbeatWorkItem(ctx context.Context, request WorkItemHeartbeatRequest) error {
	if r == nil || r.Postgres == nil {
		return nil
	}
	return r.Postgres.HeartbeatWorkItem(ctx, request)
}

func (r *Repository) GetWorkItems(ctx context.Context, campaignID, batchID, status, itemType, artifactName, target string, limit, offset int) ([]WorkItem, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.QueryWorkItems(ctx, campaignID, batchID, status, itemType, artifactName, target, limit, offset)
}

func (r *Repository) GetWorkItemByWorkflowID(ctx context.Context, workflowID string) (*WorkItem, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.GetWorkItemByWorkflowID(ctx, workflowID)
}

func (r *Repository) CountWorkItemsByStatus(ctx context.Context, campaignID, batchID, itemType, artifactName string) (map[string]int, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.CountWorkItemsByStatus(ctx, campaignID, batchID, itemType, artifactName)
}

func (r *Repository) GetWorkItemProgressSummary(ctx context.Context, filter WorkItemFilter) (WorkItemProgressSummary, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemProgressSummary{ByStatus: map[string]int{}}, nil
	}
	return r.Postgres.GetWorkItemProgressSummary(ctx, filter)
}

func (r *Repository) RetryWorkItems(ctx context.Context, request WorkItemRetryRequest) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.RetryWorkItems(ctx, request)
}

func (r *Repository) ResumeWorkItems(ctx context.Context, filter WorkItemFilter) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.ResumeWorkItems(ctx, filter)
}

func (r *Repository) PauseWorkItems(ctx context.Context, filter WorkItemFilter) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.PauseWorkItems(ctx, filter)
}

func (r *Repository) RecoverFailedWorkItems(ctx context.Context, filter WorkItemFilter, limit int) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.RecoverFailedWorkItems(ctx, filter, limit)
}

func (r *Repository) ListExpiredLeaseWorkItems(ctx context.Context, filter WorkItemFilter, limit int) ([]WorkItem, error) {
	if r == nil || r.Postgres == nil {
		return nil, nil
	}
	return r.Postgres.ListExpiredLeaseWorkItems(ctx, filter, limit)
}

func (r *Repository) ReclaimWorkItemsByWorkflowIDs(ctx context.Context, workflowIDs []string) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil || len(workflowIDs) == 0 {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.ReclaimWorkItemsByWorkflowIDs(ctx, workflowIDs)
}

func (r *Repository) RequeueEligibleRetryWorkItems(ctx context.Context, filter WorkItemFilter, minAgeSeconds, limit int) (WorkItemBulkResult, error) {
	if r == nil || r.Postgres == nil {
		return WorkItemBulkResult{}, nil
	}
	return r.Postgres.RequeueEligibleRetryWorkItems(ctx, filter, minAgeSeconds, limit)
}
