package data

import (
	"context"
	"sort"
	"time"
)

func (r *Repository) GetCampaignRuntimeView(ctx context.Context, campaignID, batchID string) (CampaignRuntimeView, error) {
	filter := WorkItemFilter{CampaignID: campaignID, BatchID: batchID}
	summary, err := r.GetWorkItemProgressSummary(ctx, filter)
	if err != nil {
		return CampaignRuntimeView{}, err
	}
	artifactStats, err := r.GetArtifactStatSummary(ctx, campaignID, "", "", "")
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
	view.BlockedQueues = blockedRuntimeQueuesForPlan(summary.ByQueue, view.ExecutionPlan)
	view.SlowTargets = slowRuntimeTargets(summary.ByTarget)
	view.ArtifactHealth = artifactRuntimeHealth(artifactStats)
	view.ETA = runtimeETA(summary)
	return view, nil
}

func inferRuntimePhase(summary WorkItemProgressSummary) string {
	if hasOpenType(summary, "dns_preflight") {
		return CampaignPhaseBootstrap
	}
	if hasOpenType(summary, "portscan_chunk") || hasOpenType(summary, "planned_dag_followup") || hasOpenType(summary, "fingers_action") {
		return CampaignPhaseDiscovery
	}
	if hasOpenType(summary, "spray_shard") {
		return CampaignPhaseExpansion
	}
	if hasOpenType(summary, "nuclei_group") {
		return CampaignPhaseVerification
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
		allowed["spray_shard"] = true
	case CampaignPhaseExpansion:
		allowed["spray_shard"] = true
		allowed["fingers_action"] = true
	case CampaignPhaseVerification:
		allowed["nuclei_group"] = true
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

func runtimePlanDefinitions() []runtimePlanDefinition {
	return []runtimePlanDefinition{
		{Type: "dns_preflight", Queue: "dns", Artifact: "dnsx", Phase: CampaignPhaseBootstrap},
		{Type: "portscan_chunk", Queue: "portscan", Artifact: "gogo", Phase: CampaignPhaseDiscovery},
		{Type: "planned_dag_followup", Queue: "planner", Artifact: "planned_dag", Phase: CampaignPhaseDiscovery},
		{Type: "fingers_action", Queue: "http", Artifact: "fingers", Phase: CampaignPhaseDiscovery},
		{Type: "spray_shard", Queue: "spray", Artifact: "spray", Phase: CampaignPhaseDiscovery},
		{Type: "nuclei_group", Queue: "nuclei", Artifact: "nuclei", Phase: CampaignPhaseVerification},
	}
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
			Type:         def.Type,
			Queue:        def.Queue,
			Artifact:     def.Artifact,
			Phase:        def.Phase,
			Allowed:      allowed,
			Pending:      group.Pending,
			Starting:     group.Starting,
			Running:      group.Running,
			Completed:    group.Completed,
			Failed:       group.Failed,
			Dead:         group.Dead,
			RetryWaiting: group.RetryWaiting,
			Paused:       group.Paused,
			StaleRunning: group.StaleRunning + group.HeartbeatStaleRunning,
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
	switch NormalizeCampaignPhase(phase) {
	case CampaignPhaseBootstrap:
		return itemType == "dns_preflight"
	case CampaignPhaseDiscovery:
		switch itemType {
		case "portscan_chunk", "planned_dag_followup", "fingers_action", "spray_shard":
			return true
		}
	case CampaignPhaseExpansion:
		switch itemType {
		case "spray_shard", "fingers_action":
			return true
		}
	case CampaignPhaseVerification:
		return itemType == "nuclei_group"
	case CampaignPhaseSteady:
		return true
	}
	return false
}

func runtimePlanState(item RuntimePlanItem, group WorkItemGroupSummary, phase string) (string, string) {
	open := openWorkItemGroup(group)
	if item.StaleRunning > 0 {
		return "blocked", "running work is stale"
	}
	if !item.Allowed {
		if open > 0 {
			return "waiting_phase", "not admitted in current " + NormalizeCampaignPhase(phase) + " phase"
		}
		return "idle", "no work created for this phase"
	}
	if group.Running+group.Starting > 0 {
		return "running", "actively executing"
	}
	if group.Pending > 0 {
		return "queued", "eligible and waiting for capacity"
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
		if group.StaleRunning > 0 || group.HeartbeatStaleRunning > 0 {
			return group.Key + " has stale running work"
		}
	}
	for _, group := range open {
		if group.Running == 0 && group.Starting == 0 && group.Queued > 0 {
			return group.Key + " is eligible and waiting for scheduler or capacity"
		}
	}
	for _, group := range open {
		if group.RetryWaiting > 0 && group.Pending == 0 && group.Running == 0 && group.Starting == 0 {
			return group.Key + " is waiting for retry delay"
		}
	}
	return NormalizeCampaignPhase(phase) + " phase still has open work"
}

func blockedRuntimeQueues(groups []WorkItemGroupSummary) []QueueRuntimeState {
	return blockedRuntimeQueuesForPlan(groups, nil)
}

func blockedRuntimeQueuesForPlan(groups []WorkItemGroupSummary, plan []RuntimePlanItem) []QueueRuntimeState {
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
		state := QueueRuntimeState{
			Queue:        group.Key,
			Pending:      group.Pending,
			Starting:     group.Starting,
			Running:      group.Running,
			RetryWaiting: group.RetryWaiting,
			Paused:       group.Paused,
			StaleRunning: group.StaleRunning + group.HeartbeatStaleRunning,
			LastError:    group.LastError,
		}
		switch {
		case state.StaleRunning > 0:
			state.Reason = "running work is stale"
		case group.Paused > 0:
			state.Reason = "queue contains paused work"
		case group.RetryWaiting > 0 && group.Pending == 0 && group.Running == 0 && group.Starting == 0:
			state.Reason = "all open work is waiting for retry"
		case group.Queued > 0 && group.Running == 0 && group.Starting == 0:
			state.Reason = "eligible work is waiting for scheduler or capacity"
		default:
			continue
		}
		out = append(out, state)
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
			Running:                group.Running + group.Starting,
			Failed:                 group.Failed,
			Dead:                   group.Dead,
			ETASeconds:             group.ETASeconds,
			OldestRunningStartedAt: group.OldestRunningStartedAt,
			LastError:              group.LastError,
		}
		switch {
		case group.StaleRunning > 0 || group.HeartbeatStaleRunning > 0:
			state.Reason = "stale running work"
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
			TotalRuns:        stat.TotalRuns,
			Requests:         stat.Requests,
			Results:          stat.Results,
			Errors:           stat.Errors,
			ErrorRatePercent: stat.ErrorRatePercent,
			ThroughputPerMin: stat.ThroughputPerMin,
		}
		switch {
		case stat.TotalRuns == 0:
			health.Reason = "no runs observed"
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
		return out[i].TotalRuns > out[j].TotalRuns
	})
	return out
}

func runtimeETA(summary WorkItemProgressSummary) ETARuntimeState {
	if summary.Overall.Queued+summary.Overall.Running+summary.Overall.Starting == 0 {
		return ETARuntimeState{Confidence: "none", Reason: "no open work remains"}
	}
	if summary.ETASeconds <= 0 {
		return ETARuntimeState{Confidence: "none", Reason: "no throughput or duration baseline yet"}
	}
	if summary.ThroughputPerMin > 0 {
		return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "medium", Reason: "based on recent completed work throughput"}
	}
	if summary.Overall.AvgDurationMs > 0 && summary.Overall.Running+summary.Overall.Starting > 0 {
		return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "low", Reason: "based on average duration and active worker count"}
	}
	return ETARuntimeState{Seconds: summary.ETASeconds, Confidence: "low", Reason: "limited runtime history"}
}

func openWorkItemGroup(group WorkItemGroupSummary) int {
	return group.Pending + group.Starting + group.Running + group.RetryWaiting + group.Paused
}
