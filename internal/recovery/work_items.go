package recovery

import (
	"context"
	"errors"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
)

const (
	ExpiredLeaseRecovered                  = "recovered"
	ExpiredLeaseSkippedTemporalUnavailable = "skipped_temporal_unavailable"
)

type CheckErrorHandler func(workflowID, workItemID string, err error)

type RecoveryPolicy struct {
	Filter               data.WorkItemFilter
	Limit                int
	RecoverFailures      bool
	RecoverExpiredLeases bool
	RequeueRetryWaiting  bool
	RetryDelaySeconds    int
	OnCheckError         CheckErrorHandler `json:"-"`
}

type RecoveryResult struct {
	RecoveredFailures      data.WorkItemBulkResult  `json:"recovered_failures"`
	RecoveredExpiredLeases data.WorkItemBulkResult  `json:"recovered_expired_leases"`
	RequeuedRetries        data.WorkItemBulkResult  `json:"requeued_retries"`
	Batches                []data.WorkItemBulkBatch `json:"batches,omitempty"`
	ExpiredLeaseStatus     string                   `json:"expired_lease_status,omitempty"`
}

func (r RecoveryResult) BulkResult() data.WorkItemBulkResult {
	return MergeWorkItemBulkResults(MergeWorkItemBulkResults(r.RecoveredFailures, r.RecoveredExpiredLeases), r.RequeuedRetries)
}

func RecoverWorkItems(ctx context.Context, repo *data.Repository, temporalClient client.Client, policy RecoveryPolicy) (RecoveryResult, error) {
	var result RecoveryResult
	if repo == nil {
		return result, nil
	}
	limit := policy.Limit
	if limit <= 0 {
		limit = 1000
	}
	if policy.RecoverFailures {
		recovered, err := repo.RecoverFailedWorkItems(ctx, policy.Filter, limit)
		if err != nil {
			return result, err
		}
		result.RecoveredFailures = recovered
	}
	if policy.RecoverExpiredLeases {
		recovered, status, err := recoverExpiredLeaseOrphans(ctx, repo, temporalClient, policy.Filter, limit, policy.OnCheckError)
		if err != nil {
			return result, err
		}
		result.RecoveredExpiredLeases = recovered
		result.ExpiredLeaseStatus = status
	}
	if policy.RequeueRetryWaiting {
		requeued, err := repo.RequeueEligibleRetryWorkItems(ctx, policy.Filter, policy.RetryDelaySeconds, limit)
		if err != nil {
			return result, err
		}
		result.RequeuedRetries = requeued
	}
	result.Batches = result.BulkResult().Batches
	return result, nil
}

func recoverExpiredLeaseOrphans(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
	if repo == nil {
		return data.WorkItemBulkResult{}, "", nil
	}
	if temporalClient == nil {
		return data.WorkItemBulkResult{}, ExpiredLeaseSkippedTemporalUnavailable, nil
	}
	items, err := repo.ListExpiredLeaseWorkItems(ctx, filter, limit)
	if err != nil {
		return data.WorkItemBulkResult{}, "", err
	}
	workflowIDs := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		workflowID := strings.TrimSpace(item.WorkflowID)
		if workflowID == "" || seen[workflowID] {
			continue
		}
		orphaned, err := TemporalWorkflowClosedOrMissing(ctx, temporalClient, workflowID)
		if err != nil {
			if onCheckError != nil {
				onCheckError(workflowID, item.ID, err)
			}
			continue
		}
		if orphaned {
			seen[workflowID] = true
			workflowIDs = append(workflowIDs, workflowID)
		}
	}
	result, err := repo.ReclaimWorkItemsByWorkflowIDs(ctx, workflowIDs)
	if err != nil {
		return data.WorkItemBulkResult{}, "", err
	}
	return result, ExpiredLeaseRecovered, nil
}

func TemporalWorkflowClosedOrMissing(ctx context.Context, temporalClient client.Client, workflowID string) (bool, error) {
	resp, err := temporalClient.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil {
		var notFound *serviceerror.NotFound
		if errors.As(err, &notFound) {
			return true, nil
		}
		return false, err
	}
	if resp == nil || resp.WorkflowExecutionInfo == nil {
		return false, nil
	}
	return resp.WorkflowExecutionInfo.Status != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING, nil
}

func MergeWorkItemBulkResults(a, b data.WorkItemBulkResult) data.WorkItemBulkResult {
	if a.Matched == 0 && a.Updated == 0 && len(a.Batches) == 0 {
		return b
	}
	if b.Matched == 0 && b.Updated == 0 && len(b.Batches) == 0 {
		return a
	}
	out := data.WorkItemBulkResult{
		Matched: a.Matched + b.Matched,
		Updated: a.Updated + b.Updated,
	}
	batches := map[string]data.WorkItemBulkBatch{}
	for _, batch := range append(a.Batches, b.Batches...) {
		if strings.TrimSpace(batch.BatchID) == "" {
			continue
		}
		batches[batch.BatchID] = batch
	}
	out.Batches = make([]data.WorkItemBulkBatch, 0, len(batches))
	for _, batch := range batches {
		out.Batches = append(out.Batches, batch)
	}
	return out
}
