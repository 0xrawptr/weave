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
	ExpiredRunningRecovered                  = "recovered"
	ExpiredRunningSkippedTemporalUnavailable = "skipped_temporal_unavailable"
)

type CheckErrorHandler func(workflowID, workItemID string, err error)

type RecoveryPolicy struct {
	Filter                data.WorkItemFilter
	Limit                 int
	RecoverFailures       bool
	RecoverExpiredRunning bool
	RequeueRetryWaiting   bool
	RetryDelaySeconds     int
	OnCheckError          CheckErrorHandler `json:"-"`
}

type RecoveryResult struct {
	RecoverableFailures  data.WorkItemBulkResult  `json:"recoverable_failures"`
	ExpiredRunning       data.WorkItemBulkResult  `json:"expired_running"`
	RetryRequeued        data.WorkItemBulkResult  `json:"retry_requeued"`
	Batches              []data.WorkItemBulkBatch `json:"batches,omitempty"`
	ExpiredRunningStatus string                   `json:"expired_running_status,omitempty"`
}

func (r RecoveryResult) BulkResult() data.WorkItemBulkResult {
	return MergeWorkItemBulkResults(MergeWorkItemBulkResults(r.RecoverableFailures, r.ExpiredRunning), r.RetryRequeued)
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
		recovered, err := repo.RecoverStaleWorkItems(ctx, policy.Filter, limit)
		if err != nil {
			return result, err
		}
		result.RecoverableFailures = recovered
	}
	if policy.RecoverExpiredRunning {
		recovered, status, err := recoverExpiredRunningOrphans(ctx, repo, temporalClient, policy.Filter, limit, policy.OnCheckError)
		if err != nil {
			return result, err
		}
		result.ExpiredRunning = recovered
		result.ExpiredRunningStatus = status
	}
	if policy.RequeueRetryWaiting {
		requeued, err := repo.RequeueRetryWaitingWorkItems(ctx, policy.Filter, policy.RetryDelaySeconds, limit)
		if err != nil {
			return result, err
		}
		result.RetryRequeued = requeued
	}
	result.Batches = result.BulkResult().Batches
	return result, nil
}

func RecoverStaleAndExpiredRunning(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
	result, err := RecoverWorkItems(ctx, repo, temporalClient, RecoveryPolicy{
		Filter:                filter,
		Limit:                 limit,
		RecoverFailures:       true,
		RecoverExpiredRunning: true,
		OnCheckError:          onCheckError,
	})
	if err != nil {
		return result.BulkResult(), result.ExpiredRunningStatus, err
	}
	return result.BulkResult(), result.ExpiredRunningStatus, nil
}

func RecoverExpiredRunningOrphans(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
	return recoverExpiredRunningOrphans(ctx, repo, temporalClient, filter, limit, onCheckError)
}

func recoverExpiredRunningOrphans(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
	if repo == nil {
		return data.WorkItemBulkResult{}, "", nil
	}
	if temporalClient == nil {
		return data.WorkItemBulkResult{}, ExpiredRunningSkippedTemporalUnavailable, nil
	}
	items, err := repo.ListExpiredRunningWorkItems(ctx, filter, limit)
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
	result, err := repo.RecoverWorkItemsByWorkflowIDs(ctx, workflowIDs)
	if err != nil {
		return data.WorkItemBulkResult{}, "", err
	}
	return result, ExpiredRunningRecovered, nil
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
