package data

import "testing"

func TestCanTransitionWorkItemStatus(t *testing.T) {
	tests := []struct {
		from string
		to   string
		want bool
	}{
		{WorkItemStatusPending, WorkItemStatusRunning, true},
		{WorkItemStatusRunning, WorkItemStatusCompleted, true},
		{WorkItemStatusRunning, WorkItemStatusFailed, true},
		{WorkItemStatusRunning, WorkItemStatusSkipped, true},
		{WorkItemStatusFailed, WorkItemStatusRetryWaiting, true},
		{WorkItemStatusRetryWaiting, WorkItemStatusPending, true},
		{WorkItemStatusPaused, WorkItemStatusPending, true},
		{WorkItemStatusDead, WorkItemStatusCompleted, true},
		{WorkItemStatusDead, WorkItemStatusSkipped, true},
		{WorkItemStatusRunning, WorkItemStatusPending, false},
		{WorkItemStatusCompleted, WorkItemStatusRunning, false},
		{WorkItemStatusDead, WorkItemStatusPending, false},
		{WorkItemStatusDead, WorkItemStatusRunning, false},
		{WorkItemStatusCancelled, WorkItemStatusRunning, false},
	}

	for _, tt := range tests {
		if got := CanTransitionWorkItemStatus(tt.from, tt.to); got != tt.want {
			t.Fatalf("CanTransitionWorkItemStatus(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestValidWorkItemStatus(t *testing.T) {
	if !ValidWorkItemStatus(WorkItemStatusRunning) {
		t.Fatalf("running should be valid")
	}
	if ValidWorkItemStatus("unknown") {
		t.Fatalf("unknown status should be invalid")
	}
}

func TestCanTransferWorkItemLease(t *testing.T) {
	if canTransferWorkItemLease(WorkItemStatusRunning, WorkItemStatusCompleted) {
		t.Fatalf("running -> completed should not allow workflow ownership transfer")
	}
	if canTransferWorkItemLease(WorkItemStatusPending, WorkItemStatusRunning) {
		t.Fatalf("pending -> running should not allow workflow ownership transfer")
	}
}

func TestRecoverableWorkItemExecutionError(t *testing.T) {
	for _, message := range []string{
		"activity heartbeat timeout",
		"context canceled",
		"worker shutdown requested",
		"activity canceled by worker drain",
		"child workflow execution already started",
		"workflow execution already started",
	} {
		if !recoverableWorkItemExecutionError(message) {
			t.Fatalf("expected recoverable execution error for %q", message)
		}
	}
	if recoverableWorkItemExecutionError("gogo scan failed: invalid ports") {
		t.Fatalf("business execution errors should not be treated as recoverable infrastructure failures")
	}
}
