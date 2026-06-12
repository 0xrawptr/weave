package data

import "testing"

func TestCanTransitionWorkItemStatus(t *testing.T) {
	tests := []struct {
		from string
		to   string
		want bool
	}{
		{WorkItemStatusPending, WorkItemStatusStarting, true},
		{WorkItemStatusStarting, WorkItemStatusRunning, true},
		{WorkItemStatusStarting, WorkItemStatusCompleted, true},
		{WorkItemStatusStarting, WorkItemStatusRetryWaiting, true},
		{WorkItemStatusRunning, WorkItemStatusCompleted, true},
		{WorkItemStatusRunning, WorkItemStatusFailed, true},
		{WorkItemStatusRunning, WorkItemStatusSkipped, true},
		{WorkItemStatusFailed, WorkItemStatusRetryWaiting, true},
		{WorkItemStatusRetryWaiting, WorkItemStatusPending, true},
		{WorkItemStatusPaused, WorkItemStatusPending, true},
		{WorkItemStatusDead, WorkItemStatusCompleted, true},
		{WorkItemStatusDead, WorkItemStatusSkipped, true},
		{WorkItemStatusStarting, WorkItemStatusPending, false},
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
	if !ValidWorkItemStatus(WorkItemStatusStarting) {
		t.Fatalf("starting should be valid")
	}
	if ValidWorkItemStatus("unknown") {
		t.Fatalf("unknown status should be invalid")
	}
}
