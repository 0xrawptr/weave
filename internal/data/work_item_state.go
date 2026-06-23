package data

func ValidWorkItemStatus(status string) bool {
	switch status {
	case WorkItemStatusPending,
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
		return to == WorkItemStatusRunning ||
			to == WorkItemStatusPaused ||
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
