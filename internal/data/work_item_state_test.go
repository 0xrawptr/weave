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

func TestWorkItemStatusPredicates(t *testing.T) {
	if !OpenWorkItemStatus(WorkItemStatusPending) || !OpenWorkItemStatus(WorkItemStatusRunning) || !OpenWorkItemStatus(WorkItemStatusRetryWaiting) || !OpenWorkItemStatus(WorkItemStatusPaused) {
		t.Fatalf("expected pending/running/retry_waiting/paused to be open")
	}
	if OpenWorkItemStatus(WorkItemStatusCompleted) || OpenWorkItemStatus(WorkItemStatusSkipped) {
		t.Fatalf("completed/skipped should not be open")
	}
	if !AdmissionBlockingWorkItemStatus(WorkItemStatusCompleted) {
		t.Fatalf("completed work should block admission dedup")
	}
	if AdmissionBlockingWorkItemStatus(WorkItemStatusSkipped) {
		t.Fatalf("skipped work should not block admission dedup")
	}
	if !PlannerBlockingActionStatus(WorkItemStatusSkipped) {
		t.Fatalf("skipped action should block planner coverage")
	}
	if PlannerBlockingActionStatus(WorkItemStatusDead) {
		t.Fatalf("dead action should not block planner coverage")
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
