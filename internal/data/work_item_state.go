package data

func ValidWorkItemStatus(status string) bool {
	switch status {
	case WorkItemStatusPending,
		WorkItemStatusDispatching,
		WorkItemStatusRunning,
		WorkItemStatusCompleted,
		WorkItemStatusFailed,
		WorkItemStatusRetryWaiting,
		WorkItemStatusPaused,
		WorkItemStatusCancelled,
		WorkItemStatusSkipped,
		WorkItemStatusDead:
		return true
	default:
		return false
	}
}

func CanTransitionWorkItemStatus(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "":
		return to == WorkItemStatusPending
	case WorkItemStatusPending:
		return to == WorkItemStatusDispatching ||
			to == WorkItemStatusRunning ||
			to == WorkItemStatusPaused ||
			to == WorkItemStatusCancelled ||
			to == WorkItemStatusSkipped ||
			to == WorkItemStatusDead
	case WorkItemStatusDispatching:
		return to == WorkItemStatusRunning ||
			to == WorkItemStatusCompleted ||
			to == WorkItemStatusFailed ||
			to == WorkItemStatusRetryWaiting ||
			to == WorkItemStatusCancelled ||
			to == WorkItemStatusSkipped ||
			to == WorkItemStatusDead
	case WorkItemStatusRunning:
		return to == WorkItemStatusCompleted ||
			to == WorkItemStatusFailed ||
			to == WorkItemStatusRetryWaiting ||
			to == WorkItemStatusCancelled ||
			to == WorkItemStatusSkipped ||
			to == WorkItemStatusDead
	case WorkItemStatusFailed:
		return to == WorkItemStatusRetryWaiting ||
			to == WorkItemStatusPending ||
			to == WorkItemStatusDead
	case WorkItemStatusRetryWaiting:
		return to == WorkItemStatusPending ||
			to == WorkItemStatusPaused ||
			to == WorkItemStatusCancelled ||
			to == WorkItemStatusDead
	case WorkItemStatusPaused:
		return to == WorkItemStatusPending ||
			to == WorkItemStatusCancelled ||
			to == WorkItemStatusDead
	case WorkItemStatusDead:
		return to == WorkItemStatusCompleted ||
			to == WorkItemStatusSkipped
	default:
		return false
	}
}

func TerminalWorkItemStatus(status string) bool {
	switch status {
	case WorkItemStatusCompleted, WorkItemStatusCancelled, WorkItemStatusSkipped, WorkItemStatusDead:
		return true
	default:
		return false
	}
}

func OpenWorkItemStatus(status string) bool {
	switch status {
	case WorkItemStatusPending, WorkItemStatusDispatching, WorkItemStatusRunning, WorkItemStatusRetryWaiting, WorkItemStatusPaused:
		return true
	default:
		return false
	}
}

func failureWorkItemStatus(attempts, maxAttempts int) string {
	if attempts < maxAttempts {
		return WorkItemStatusRetryWaiting
	}
	return WorkItemStatusDead
}

// Admission blocking statuses prevent duplicate work from being admitted once
// equivalent work is queued, active, retryable, paused, or already completed.
func AdmissionBlockingWorkItemStatus(status string) bool {
	switch status {
	case WorkItemStatusPending,
		WorkItemStatusDispatching,
		WorkItemStatusRunning,
		WorkItemStatusCompleted,
		WorkItemStatusRetryWaiting,
		WorkItemStatusPaused:
		return true
	default:
		return false
	}
}

// Planner blocking statuses suppress equivalent follow-up actions that are
// already planned, active, completed, retryable, paused, or intentionally skipped.
func PlannerBlockingActionStatus(status string) bool {
	switch status {
	case WorkItemStatusPending,
		WorkItemStatusDispatching,
		WorkItemStatusRunning,
		WorkItemStatusCompleted,
		WorkItemStatusRetryWaiting,
		WorkItemStatusPaused,
		WorkItemStatusSkipped:
		return true
	default:
		return false
	}
}
