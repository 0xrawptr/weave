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

func RecoverStaleAndExpiredRunning(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
	if repo == nil {
		return data.WorkItemBulkResult{}, "", nil
	}
	failed, err := repo.RecoverStaleWorkItems(ctx, filter, limit)
	if err != nil {
		return data.WorkItemBulkResult{}, "", err
	}
	orphaned, status, err := RecoverExpiredRunningOrphans(ctx, repo, temporalClient, filter, limit, onCheckError)
	if err != nil {
		return failed, status, err
	}
	return MergeWorkItemBulkResults(failed, orphaned), status, nil
}

func RecoverExpiredRunningOrphans(ctx context.Context, repo *data.Repository, temporalClient client.Client, filter data.WorkItemFilter, limit int, onCheckError CheckErrorHandler) (data.WorkItemBulkResult, string, error) {
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
