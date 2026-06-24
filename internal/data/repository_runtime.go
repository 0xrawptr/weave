package data

import (
	"context"
	"sort"
	"time"
)

func (r *Repository) GetCampaignRuntimeView(ctx context.Context, campaignID, batchID string) (CampaignRuntimeView, error) {
	return r.GetCampaignRuntimeViewWithCapacity(ctx, campaignID, batchID, nil)
}

func (r *Repository) GetCampaignRuntimeViewWithCapacity(ctx context.Context, campaignID, batchID string, sdkCapacityOverrides map[string]int) (CampaignRuntimeView, error) {
	filter := WorkItemFilter{CampaignID: campaignID, BatchID: batchID}
	summary, err := r.GetWorkItemProgressSummary(ctx, filter)
	if err != nil {
		return CampaignRuntimeView{}, err
	}
	artifactStats, err := r.GetArtifactStatSummary(ctx, campaignID, "", "", "")
	if err != nil {
		return CampaignRuntimeView{}, err
	}
	capacity, err := r.GetSchedulerCapacities(ctx, campaignID, batchID)
	if err != nil {
		return CampaignRuntimeView{}, err
	}
	var campaign *Campaign
	if campaignID != "" {
		campaign, _ = r.GetCampaign(ctx, campaignID)
	}
	var events []CampaignPhaseEvent
	if campaignID != "" {
		events, _ = r.GetCampaignPhaseEvents(ctx, campaignID, 20, 0)
	}
	view := CampaignRuntimeView{
		Campaign:          campaign,
		Summary:           summary,
		RecentPhaseEvents: events,
		GeneratedAt:       time.Now(),
	}
	if campaign != nil {
		view.Phase = NormalizeCampaignPhase(campaign.Phase)
		view.PhaseReason = campaign.PhaseReason
	} else {
		view.Phase = inferRuntimePhase(summary)
	}
	view.OpenPhaseWork = openRuntimePhaseWork(view.Phase, summary)
	view.PhaseBlockingReason = runtimePhaseBlockingReason(view.Phase, view.OpenPhaseWork, summary)
	view.ExecutionPlan = runtimeExecutionPlan(view.Phase, summary)
	view.RuntimeQueues = runtimeQueuesForPlan(summary.ByQueue, view.ExecutionPlan)
	view.BlockedQueues = blockedRuntimeQueues(view.RuntimeQueues)
	view.SlowTargets = slowRuntimeTargets(summary.ByTarget)
	view.ArtifactHealth = artifactRuntimeHealth(artifactStats)
	view.ProblemArtifacts = problemRuntimeArtifacts(view.ArtifactHealth)
	view.CapacityDecisions = capacityDecisionSnapshots(capacity)
	view.CapacityProfiles = RuntimeCapacityProfiles(sdkCapacityOverrides)
	view.ETA = runtimeETA(summary)
	view.CurrentBottleneck = runtimeCurrentBottleneck(view)
	view.RuntimeWarnings = runtimeWarnings(view)
	return view, nil
}

func inferRuntimePhase(summary WorkItemProgressSummary) string {
	if hasOpenType(summary, "dns_preflight") {
		return CampaignPhaseBootstrap
	}
	if hasOpenType(summary, "portscan_chunk") || hasOpenType(summary, "planned_dag_followup") || hasOpenType(summary, "fingers_action") {
		return CampaignPhaseDiscovery
	}
	if hasOpenType(summary, "nuclei_group") {
		return CampaignPhaseVerification
	}
	if hasOpenType(summary, "spray_shard") {
		return CampaignPhaseExpansion
	}
	return CampaignPhaseSteady
}

func hasOpenType(summary WorkItemProgressSummary, itemType string) bool {
	for _, group := range summary.ByType {
		if group.Key == itemType && openWorkItemGroup(group) > 0 {
			return true
		}
	}
	return false
}

func openRuntimePhaseWork(phase string, summary WorkItemProgressSummary) []WorkItemGroupSummary {
	allowed := map[string]bool{}
	switch NormalizeCampaignPhase(phase) {
	case CampaignPhaseBootstrap:
		allowed["dns_preflight"] = true
	case CampaignPhaseDiscovery:
		allowed["portscan_chunk"] = true
		allowed["planned_dag_followup"] = true
		allowed["fingers_action"] = true
	case CampaignPhaseExpansion:
		allowed["spray_shard"] = true
		allowed["fingers_action"] = true
	case CampaignPhaseVerification:
		allowed["nuclei_group"] = true
		allowed["spray_shard"] = true
	case CampaignPhaseSteady:
		for _, group := range summary.ByType {
			if openWorkItemGroup(group) > 0 {
				allowed[group.Key] = true
			}
		}
	}
	out := make([]WorkItemGroupSummary, 0, len(summary.ByType))
	for _, group := range summary.ByType {
		if allowed[group.Key] && openWorkItemGroup(group) > 0 {
			out = append(out, group)
		}
	}
	return out
}

type runtimePlanDefinition struct {
	Type     string
	Queue    string
	Artifact string
	Phase    string
}

func runtimeWorkCountsFromGroup(group WorkItemGroupSummary) RuntimeWorkCounts {
	return RuntimeWorkCounts{
		Pending:           group.Pending,
		Running:           group.Running,
		Completed:         group.Completed,
		Failed:            group.Failed,
		Dead:              group.Dead,
		RetryWaiting:      group.RetryWaiting,
		Paused:            group.Paused,
		StalledRunning:    group.StalledRunning,
		NoProgressRunning: noProgressRunning(group),
		ProgressPercent:   group.ProgressPercent,
		ETASeconds:        group.ETASeconds,
		LastError:         group.LastError,
	}
}

func runtimePlanDefinitions() []runtimePlanDefinition {
	defs := WorkItemDefinitions()
	out := make([]runtimePlanDefinition, 0, len(defs))
	for _, def := range defs {
		artifact := def.RuntimeArtifact
		if artifact == "" {
			artifact = def.Artifact
		}
		out = append(out, runtimePlanDefinition{
			Type:     def.Type,
			Queue:    def.Queue,
			Artifact: artifact,
			Phase:    def.PrimaryPhase,
		})
	}
	return out
}

func runtimeExecutionPlan(phase string, summary WorkItemProgressSummary) []RuntimePlanItem {
	phase = NormalizeCampaignPhase(phase)
	groups := map[string]WorkItemGroupSummary{}
	for _, group := range summary.ByType {
		groups[group.Key] = group
	}
	out := make([]RuntimePlanItem, 0, len(runtimePlanDefinitions()))
	for _, def := range runtimePlanDefinitions() {
		group := groups[def.Type]
		allowed := runtimeTypeAllowedInPhase(phase, def.Type)
		item := RuntimePlanItem{
			Type:              def.Type,
			Queue:             def.Queue,
			Artifact:          def.Artifact,
			Phase:             def.Phase,
			RuntimeWorkCounts: runtimeWorkCountsFromGroup(group),
			Allowed:           allowed,
		}
		item.State, item.Reason = runtimePlanState(item, group, phase)
		if !allowed && openWorkItemGroup(group) > 0 {
			item.NextPhase = def.Phase
			item.BlockingReason = "waiting for " + def.Phase + " phase"
		}
		out = append(out, item)
	}
	return out
}

func runtimeTypeAllowedInPhase(phase, itemType string) bool {
	return WorkItemTypeAllowedInPhase(phase, itemType)
}

func runtimePlanState(item RuntimePlanItem, group WorkItemGroupSummary, phase string) (string, string) {
	open := openWorkItemGroup(group)
	if item.StalledRunning > 0 {
		return "blocked", "running work has no valid progress heartbeat"
	}
	if !item.Allowed {
		if open > 0 {
			return "waiting_phase", "not admitted in current " + NormalizeCampaignPhase(phase) + " phase"
		}
		return "idle", "no work created for this phase"
	}
	if group.Running > 0 {
		return "running", "actively executing"
	}
	if group.Pending > 0 {
		return "queued", "eligible and waiting for scheduler admission"
	}
	if group.RetryWaiting > 0 {
		return "retry_waiting", "waiting for retry delay"
	}
	if group.Paused > 0 {
		return "paused", "paused by operator"
	}
	if group.Failed+group.Dead > 0 {
		return "error", "failed or dead work remains"
	}
	if group.Completed+group.Skipped+group.Cancelled > 0 {
		return "done", "completed for current backlog"
	}
	return "idle", "no work created"
}

func runtimePhaseBlockingReason(phase string, open []WorkItemGroupSummary, summary WorkItemProgressSummary) string {
	if summary.Total == 0 {
		return "no work items have been created"
	}
	if len(open) == 0 {
		if summary.Overall.Error > 0 {
			return "phase has no open work but failed/dead work items exist"
		}
		return "phase has no open work"
	}
	for _, group := range open {
		if group.StalledRunning > 0 {
			return group.Key + " has running work without a valid progress heartbeat"
		}
	}
	for _, group := range open {
		if group.Running == 0 && group.Queued > 0 {
			return group.Key + " is eligible and waiting for scheduler admission"
		}
	}
	for _, group := range open {
		if group.RetryWaiting > 0 && group.Pending == 0 && group.Running == 0 {
			return group.Key + " is waiting for retry delay"
		}
	}
	return NormalizeCampaignPhase(phase) + " phase still has open work"
}

func runtimeQueuesForPlan(groups []WorkItemGroupSummary, plan []RuntimePlanItem) []QueueRuntimeState {
	allowedQueues := map[string]bool{}
	if len(plan) > 0 {
		for _, item := range plan {
			if item.Allowed {
				allowedQueues[item.Queue] = true
			}
		}
	}
	out := make([]QueueRuntimeState, 0, len(groups))
	for _, group := range groups {
		if len(allowedQueues) > 0 && !allowedQueues[group.Key] {
			continue
		}
		open := openWorkItemGroup(group)
		if open == 0 {
			continue
		}
		state := QueueRuntimeState{Queue: group.Key, RuntimeWorkCounts: runtimeWorkCountsFromGroup(group)}
		switch {
		case state.StalledRunning > 0:
			state.Reason = "running work has no valid progress heartbeat"
		case group.Paused > 0:
			state.Reason = "queue contains paused work"
		case group.RetryWaiting > 0 && group.Pending == 0 && group.Running == 0:
			state.Reason = "all open work is waiting for retry"
		case group.Queued > 0 && group.Running == 0:
			state.Reason = "eligible work is waiting for scheduler admission"
		case group.Running > 0:
			state.Reason = "actively executing"
		case group.Queued > 0:
			state.Reason = "queued backlog"
		default:
			state.Reason = "open work exists"
		}
		out = append(out, state)
	}
	return out
}

func blockedRuntimeQueues(queues []QueueRuntimeState) []QueueRuntimeState {
	out := make([]QueueRuntimeState, 0, len(queues))
	for _, queue := range queues {
		switch {
		case queue.StalledRunning > 0:
			out = append(out, queue)
		case queue.Paused > 0:
			out = append(out, queue)
		case queue.RetryWaiting > 0 && queue.Pending == 0 && queue.Running == 0:
			out = append(out, queue)
		case queue.Pending > 0 && queue.Running == 0:
			out = append(out, queue)
		}
	}
	return out
}

func capacityDecisionSnapshots(capacities []SchedulerCapacity) []SchedulerCapacity {
	out := make([]SchedulerCapacity, 0, len(capacities))
	for _, capacity := range capacities {
		capacity.SnapshotKind = schedulerCapacitySnapshotKind
		capacity.SnapshotNote = schedulerCapacitySnapshotNote
		out = append(out, capacity)
	}
	return out
}

func slowRuntimeTargets(groups []WorkItemGroupSummary) []TargetRuntimeState {
	candidates := make([]WorkItemGroupSummary, 0, len(groups))
	for _, group := range groups {
		if openWorkItemGroup(group) > 0 || group.Error > 0 {
			candidates = append(candidates, group)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Running != candidates[j].Running {
			return candidates[i].Running > candidates[j].Running
		}
		if candidates[i].Queued != candidates[j].Queued {
			return candidates[i].Queued > candidates[j].Queued
		}
		if candidates[i].ETASeconds != candidates[j].ETASeconds {
			return candidates[i].ETASeconds > candidates[j].ETASeconds
		}
		return candidates[i].Total > candidates[j].Total
	})
	if len(candidates) > 10 {
		candidates = candidates[:10]
	}
	out := make([]TargetRuntimeState, 0, len(candidates))
	for _, group := range candidates {
		state := TargetRuntimeState{
			Target:                 group.Key,
			Total:                  group.Total,
			Queued:                 group.Queued,
			Running:                group.Running,
			StalledRunning:         group.StalledRunning,
			Failed:                 group.Failed,
			Dead:                   group.Dead,
			ETASeconds:             group.ETASeconds,
			OldestRunningStartedAt: group.OldestRunningStartedAt,
			LastError:              group.LastError,
		}
		switch {
		case group.StalledRunning > 0:
			state.Reason = "running work has no valid progress heartbeat"
		case state.Running > 0:
			state.Reason = "currently running"
		case state.Queued > 0:
			state.Reason = "queued backlog"
		case state.Failed+state.Dead > 0:
			state.Reason = "errors remain"
		}
		out = append(out, state)
	}
	return out
}

func artifactRuntimeHealth(stats []ArtifactStatSummary) []ArtifactRuntimeHealth {
	out := make([]ArtifactRuntimeHealth, 0, len(stats))
	for _, stat := range stats {
		health := ArtifactRuntimeHealth{
			Artifact:         stat.Artifact,
			StatRecords:      stat.StatRecords,
			WorkItemRuns:     stat.WorkItemRuns,
			Requests:         stat.Requests,
			Results:          stat.Results,
			Errors:           stat.Errors,
			ErrorRatePercent: stat.ErrorRatePercent,
			ThroughputPerMin: stat.ThroughputPerMin,
		}
		switch {
		case stat.StatRecords == 0 && stat.WorkItemRuns == 0:
			health.Reason = "no execution observed"
		case stat.Errors > 0 && stat.ErrorRatePercent >= 50:
			health.Reason = "high error rate"
		case stat.Errors > 0:
			health.Reason = "errors observed"
		case stat.Results == 0:
			health.Reason = "no results observed"
		default:
			health.Reason = "healthy"
		}
		out = append(out, health)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ErrorRatePercent != out[j].ErrorRatePercent {
			return out[i].ErrorRatePercent > out[j].ErrorRatePercent
		}
		if out[i].Errors != out[j].Errors {
			return out[i].Errors > out[j].Errors
		}
		return out[i].StatRecords > out[j].StatRecords
	})
	return out
}

func problemRuntimeArtifacts(health []ArtifactRuntimeHealth) []ArtifactRuntimeHealth {
	out := make([]ArtifactRuntimeHealth, 0, len(health))
	for _, item := range health {
		if item.Errors > 0 || item.ErrorRatePercent > 0 {
			out = append(out, item)
		}
	}
	if len(out) > 10 {
		return out[:10]
	}
	return out
}

func runtimeCurrentBottleneck(view CampaignRuntimeView) *RuntimeBottleneck {
	for _, item := range view.ExecutionPlan {
		if item.StalledRunning > 0 {
			return bottleneckFromPlan("stalled_work", item, "running work has no valid progress heartbeat")
		}
	}
	for _, item := range view.ExecutionPlan {
		if item.Failed+item.Dead > 0 {
			return bottleneckFromPlan("work_error", item, "failed or dead work remains")
		}
	}
	for _, queue := range view.BlockedQueues {
		if queue.StalledRunning > 0 {
			bottleneck := &RuntimeBottleneck{
				Kind:              "queue",
				Key:               queue.Queue,
				RuntimeWorkCounts: queue.RuntimeWorkCounts,
				Queue:             queue.Queue,
				Reason:            queue.Reason,
			}
			return bottleneck
		}
	}
	if len(view.BlockedQueues) > 0 {
		queue := view.BlockedQueues[0]
		bottleneck := &RuntimeBottleneck{
			Kind:              "queue",
			Key:               queue.Queue,
			RuntimeWorkCounts: queue.RuntimeWorkCounts,
			Queue:             queue.Queue,
			Reason:            queue.Reason,
		}
		return bottleneck
	}
	for _, item := range view.ExecutionPlan {
		if item.Allowed && openRuntimePlanItem(item) > 0 {
			return bottleneckFromPlan("phase_work", item, item.Reason)
		}
	}
	for _, target := range view.SlowTargets {
		if target.Running+target.Queued+target.Failed+target.Dead > 0 {
			return &RuntimeBottleneck{
				Kind:   "target",
				Key:    target.Target,
				Target: target.Target,
				RuntimeWorkCounts: RuntimeWorkCounts{
					Pending:        target.Queued,
					Running:        target.Running,
					Failed:         target.Failed,
					Dead:           target.Dead,
					StalledRunning: target.StalledRunning,
					ETASeconds:     target.ETASeconds,
					LastError:      target.LastError,
				},
				Reason: target.Reason,
			}
		}
	}
	return nil
}

func bottleneckFromPlan(kind string, item RuntimePlanItem, reason string) *RuntimeBottleneck {
	bottleneck := &RuntimeBottleneck{
		Kind:              kind,
		Key:               item.Type,
		RuntimeWorkCounts: item.RuntimeWorkCounts,
		Phase:             item.Phase,
		Queue:             item.Queue,
		Type:              item.Type,
		Artifact:          item.Artifact,
		Reason:            reason,
	}
	return bottleneck
}

func openRuntimePlanItem(item RuntimePlanItem) int {
	return item.Pending + item.Running + item.RetryWaiting + item.Paused
}

func runtimeWarnings(view CampaignRuntimeView) []string {
	var warnings []string
	if view.Summary.Overall.StalledRunning > 0 || runtimeNoProgressRunning(view.ExecutionPlan) > 0 {
		warnings = append(warnings, "running work has no valid progress heartbeat")
	}
	if view.Summary.Overall.Failed+view.Summary.Overall.Dead > 0 {
		warnings = append(warnings, "failed or dead work items exist")
	}
	if len(view.BlockedQueues) > 0 {
		warnings = append(warnings, "one or more eligible queues are blocked")
	}
	if len(view.ProblemArtifacts) > 0 {
		warnings = append(warnings, "artifact errors observed")
	}
	if view.ETA.Confidence == "none" && view.Summary.Overall.Queued+view.Summary.Overall.Running > 0 {
		warnings = append(warnings, "ETA is unavailable for open work")
	}
	return warnings
}

func runtimeNoProgressRunning(plan []RuntimePlanItem) int {
	total := 0
	for _, item := range plan {
		total += item.NoProgressRunning
	}
	return total
}

func noProgressRunning(group WorkItemGroupSummary) int {
	if group.Running <= 0 || group.OldestRunningStartedAt == "" || group.AvgDurationMs <= 0 {
		return 0
	}
	startedAt, ok := parseRuntimeTimestamp(group.OldestRunningStartedAt)
	if !ok {
		return 0
	}
	threshold := time.Duration(group.AvgDurationMs) * time.Millisecond * 10
	if threshold < 2*time.Minute {
		threshold = 2 * time.Minute
	}
	if time.Since(startedAt) <= threshold {
		return 0
	}
	return group.Running
}

func parseRuntimeTimestamp(value string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05-07",
		"2006-01-02T15:04:05-07:00",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func runtimeETA(summary WorkItemProgressSummary) ETARuntimeState {
	if summary.Overall.Queued+summary.Overall.Running == 0 {
		return ETARuntimeState{Confidence: "none", Reason: "no open work remains"}
	}
	if summary.ETASeconds <= 0 {
		return ETARuntimeState{Confidence: "none", Reason: "no throughput or duration baseline yet"}
	}
	if summary.ThroughputPerMin > 0 {
		return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "medium", Reason: "based on recent completed work throughput"}
	}
	if summary.Overall.AvgDurationMs > 0 && summary.Overall.Running > 0 {
		return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "low", Reason: "based on average duration and active worker count"}
	}
	return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "low", Reason: "limited runtime history"}
}

func openWorkItemGroup(group WorkItemGroupSummary) int {
	return group.Pending + group.Running + group.RetryWaiting + group.Paused
}
