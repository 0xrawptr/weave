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
		{WorkItemStatusFailed, WorkItemStatusRetryWaiting, true},
		{WorkItemStatusRetryWaiting, WorkItemStatusPending, true},
		{WorkItemStatusPaused, WorkItemStatusPending, true},
		{WorkItemStatusCompleted, WorkItemStatusRunning, false},
		{WorkItemStatusDead, WorkItemStatusPending, false},
		{WorkItemStatusCancelled, WorkItemStatusRunning, false},
	}

	for _, tt := range tests {
		if got := CanTransitionWorkItemStatus(tt.from, tt.to); got != tt.want {
			t.Fatalf("CanTransitionWorkItemStatus(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestValidWorkItemStatus(t *testing.T) {
	if !ValidWorkItemStatus(WorkItemStatusRetryWaiting) {
		t.Fatalf("retry_waiting should be valid")
	}
	if ValidWorkItemStatus("unknown") {
		t.Fatalf("unknown status should be invalid")
	}
}
