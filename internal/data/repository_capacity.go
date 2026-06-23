package data

import (
	"context"
	"sort"
	"time"
)

type CapacityProfile struct {
	Queue               string
	Artifact            string
	SchedulerMin        int
	SchedulerInitial    int
	SchedulerMax        int
	SchedulerSlowMs     int64
	SchedulerErrorLimit int
	SDKDefaultCapacity  int
	SDKUnit             string
	SDKDescription      string
}

func DefaultCapacityProfiles() []CapacityProfile {
	return []CapacityProfile{
		{
			Queue: "dns", Artifact: "dnsx",
			SchedulerMin: 1, SchedulerInitial: 4, SchedulerMax: 12, SchedulerSlowMs: 30_000, SchedulerErrorLimit: 40,
			SDKUnit: "not_configured", SDKDescription: "dnsx capacity is controlled by Temporal worker slots and scheduler admission",
		},
		{
			Queue: "portscan", Artifact: "gogo",
			SchedulerMin: 1, SchedulerInitial: 4, SchedulerMax: 8, SchedulerSlowMs: 180_000, SchedulerErrorLimit: 30,
			SDKDefaultCapacity: 6000, SDKUnit: "engine_tokens", SDKDescription: "local SDK gogo engine capacity inside one worker process",
		},
		{
			Queue: "planner", Artifact: "planned_dag",
			SchedulerMin: 1, SchedulerInitial: 4, SchedulerMax: 16, SchedulerSlowMs: 10_000, SchedulerErrorLimit: 50,
			SDKUnit: "not_applicable", SDKDescription: "planner is Weave-owned logic and has no SDK engine bucket",
		},
		{
			Queue: "http", Artifact: "fingers",
			SchedulerMin: 1, SchedulerInitial: 6, SchedulerMax: 16, SchedulerSlowMs: 60_000, SchedulerErrorLimit: 40,
			SDKUnit: "not_configured", SDKDescription: "fingers capacity is controlled by Temporal worker slots and scheduler admission",
		},
		{
			Queue: "spray", Artifact: "spray",
			SchedulerMin: 1, SchedulerInitial: 3, SchedulerMax: 12, SchedulerSlowMs: 120_000, SchedulerErrorLimit: 25,
			SDKDefaultCapacity: 300, SDKUnit: "engine_tokens", SDKDescription: "local SDK spray engine capacity inside one worker process",
		},
		{
			Queue: "nuclei", Artifact: "nuclei",
			SchedulerMin: 1, SchedulerInitial: 2, SchedulerMax: 6, SchedulerSlowMs: 240_000, SchedulerErrorLimit: 30,
			SDKUnit: "not_applicable", SDKDescription: "nuclei is executed by Weave adapter without a shared SDK bucket",
		},
		{
			Queue: "bruteforce", Artifact: "zombie",
			SchedulerMin: 1, SchedulerInitial: 1, SchedulerMax: 1, SchedulerSlowMs: 300_000, SchedulerErrorLimit: 10,
			SDKDefaultCapacity: 20, SDKUnit: "engine_tokens", SDKDescription: "local SDK zombie engine capacity inside one worker process",
		},
		{
			Artifact:           "neutron",
			SDKDefaultCapacity: 30, SDKUnit: "template_executions", SDKDescription: "local SDK neutron template execution capacity inside one worker process",
		},
		{
			Artifact: "proton",
			SDKUnit:  "engine_tokens", SDKDescription: "local SDK proton engine capacity inside one worker process",
		},
	}
}

func DefaultSchedulerCapacityPolicies() []SchedulerCapacityPolicy {
	profiles := DefaultCapacityProfiles()
	out := make([]SchedulerCapacityPolicy, 0, len(profiles))
	for _, profile := range profiles {
		if profile.Queue == "" {
			continue
		}
		out = append(out, SchedulerCapacityPolicy{
			Queue:      profile.Queue,
			Artifact:   profile.Artifact,
			Min:        profile.SchedulerMin,
			Initial:    profile.SchedulerInitial,
			Max:        profile.SchedulerMax,
			SlowMs:     profile.SchedulerSlowMs,
			ErrorLimit: profile.SchedulerErrorLimit,
		})
	}
	return out
}

func DefaultSDKCapacityForArtifact(artifact string) int {
	for _, profile := range DefaultCapacityProfiles() {
		if profile.Artifact == artifact {
			return profile.SDKDefaultCapacity
		}
	}
	return 0
}

func RuntimeCapacityProfiles(sdkOverrides map[string]int) []RuntimeCapacityProfile {
	profiles := DefaultCapacityProfiles()
	out := make([]RuntimeCapacityProfile, 0, len(profiles))
	for _, profile := range profiles {
		configured := profile.SDKDefaultCapacity
		if sdkOverrides != nil && sdkOverrides[profile.Artifact] > 0 {
			configured = sdkOverrides[profile.Artifact]
		}
		item := RuntimeCapacityProfile{
			Queue:                      profile.Queue,
			Artifact:                   profile.Artifact,
			SchedulerScope:             "scheduler_admission",
			SchedulerMinCapacity:       profile.SchedulerMin,
			SchedulerInitialCapacity:   profile.SchedulerInitial,
			SchedulerMaxCapacity:       profile.SchedulerMax,
			SchedulerSlowMs:            profile.SchedulerSlowMs,
			SchedulerErrorLimitPercent: profile.SchedulerErrorLimit,
			SchedulerDescription:       "adaptive work_item dispatch capacity decided by Weave scheduler",
			SDKScope:                   "sdk_engine_bucket",
			SDKConfiguredCapacity:      configured,
			SDKDefaultCapacity:         profile.SDKDefaultCapacity,
			SDKUnit:                    profile.SDKUnit,
			SDKDescription:             profile.SDKDescription,
			ObservationNote:            "scheduler_admission is campaign-level dispatch control; sdk_engine_bucket is local to each worker process and is not a global cluster limit",
		}
		if profile.Queue == "" {
			item.SchedulerScope = "none"
			item.SchedulerDescription = "no Weave scheduler queue is bound to this SDK engine"
		}
		out = append(out, item)
	}
	return out
}

func (r *Repository) UpdateSchedulerCapacity(ctx context.Context, request SchedulerCapacityUpdateRequest) ([]SchedulerCapacity, error) {
	if r == nil || r.Postgres == nil {
		return defaultSchedulerCapacities(request), nil
	}
	return r.Postgres.UpdateSchedulerCapacity(ctx, request)
}

func (r *Repository) GetSchedulerCapacities(ctx context.Context, campaignID, batchID string) ([]SchedulerCapacity, error) {
	if r == nil || r.Postgres == nil {
		return defaultSchedulerCapacities(SchedulerCapacityUpdateRequest{CampaignID: campaignID, BatchID: batchID}), nil
	}
	return r.Postgres.GetSchedulerCapacities(ctx, campaignID, batchID)
}

func (r *Repository) EffectiveSchedulerCapacity(ctx context.Context, campaignID, batchID, queue string) (int, error) {
	if r == nil || r.Postgres == nil {
		return defaultCapacityForQueue(queue), nil
	}
	return r.Postgres.EffectiveSchedulerCapacity(ctx, campaignID, batchID, queue)
}

func (p *PostgresStore) UpdateSchedulerCapacity(ctx context.Context, request SchedulerCapacityUpdateRequest) ([]SchedulerCapacity, error) {
	summary, err := p.GetWorkItemProgressSummary(ctx, WorkItemFilter{CampaignID: request.CampaignID, BatchID: request.BatchID})
	if err != nil {
		return nil, err
	}
	stats, err := p.QueryArtifactStatSummary(ctx, request.CampaignID, "", "", "")
	if err != nil {
		return nil, err
	}
	current, err := p.GetSchedulerCapacities(ctx, request.CampaignID, request.BatchID)
	if err != nil {
		return nil, err
	}
	currentByQueue := map[string]SchedulerCapacity{}
	for _, item := range current {
		currentByQueue[item.Queue] = item
	}
	queueByKey := map[string]WorkItemGroupSummary{}
	for _, group := range summary.ByQueue {
		queueByKey[group.Key] = group
	}
	statsByArtifact := map[string]ArtifactStatSummary{}
	for _, stat := range stats {
		statsByArtifact[stat.Artifact] = stat
	}

	out := make([]SchedulerCapacity, 0, len(DefaultSchedulerCapacityPolicies()))
	for _, policy := range DefaultSchedulerCapacityPolicies() {
		group := queueByKey[policy.Queue]
		stat := statsByArtifact[policy.Artifact]
		previous := currentByQueue[policy.Queue]
		capacity := decideSchedulerCapacity(request, policy, previous, group, stat)
		if err := p.upsertSchedulerCapacity(ctx, capacity); err != nil {
			return nil, err
		}
		out = append(out, capacity)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Queue < out[j].Queue })
	return out, nil
}

func (p *PostgresStore) GetSchedulerCapacities(ctx context.Context, campaignID, batchID string) ([]SchedulerCapacity, error) {
	query := `SELECT campaign_id, batch_id, queue, artifact, min_capacity, max_capacity, effective_capacity,
		recommended_capacity, running, pending, retry_waiting, stale_running, completed, failed, dead, avg_duration_ms,
		throughput_per_min, stat_requests, stat_results, stat_errors, error_rate_percent, last_decision, decision_reason, updated_at
	FROM scheduler_capacity
	WHERE campaign_id = $1 AND batch_id = $2
	ORDER BY queue ASC`
	args := []interface{}{campaignID, batchID}
	if batchID == "" {
		query = `SELECT DISTINCT ON (queue) campaign_id, batch_id, queue, artifact, min_capacity, max_capacity, effective_capacity,
			recommended_capacity, running, pending, retry_waiting, stale_running, completed, failed, dead, avg_duration_ms,
			throughput_per_min, stat_requests, stat_results, stat_errors, error_rate_percent, last_decision, decision_reason, updated_at
		FROM scheduler_capacity
		WHERE campaign_id = $1
		ORDER BY queue ASC, updated_at DESC`
		args = []interface{}{campaignID}
	}
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SchedulerCapacity
	for rows.Next() {
		var item SchedulerCapacity
		if err := rows.Scan(&item.CampaignID, &item.BatchID, &item.Queue, &item.Artifact, &item.MinCapacity, &item.MaxCapacity, &item.EffectiveCapacity,
			&item.RecommendedCapacity, &item.Running, &item.Pending, &item.RetryWaiting, &item.StalledRunning, &item.Completed, &item.Failed, &item.Dead,
			&item.AvgDurationMs, &item.ThroughputPerMin, &item.StatRequests, &item.StatResults, &item.StatErrors, &item.ErrorRatePercent,
			&item.LastDecision, &item.DecisionReason, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return defaultSchedulerCapacities(SchedulerCapacityUpdateRequest{CampaignID: campaignID, BatchID: batchID}), nil
	}
	return out, nil
}

func (p *PostgresStore) EffectiveSchedulerCapacity(ctx context.Context, campaignID, batchID, queue string) (int, error) {
	var capacity int
	err := p.pool.QueryRow(ctx, `SELECT effective_capacity FROM scheduler_capacity WHERE campaign_id = $1 AND batch_id = $2 AND queue = $3`, campaignID, batchID, queue).Scan(&capacity)
	if err != nil {
		return defaultCapacityForQueue(queue), nil
	}
	return capacity, nil
}

func (p *PostgresStore) upsertSchedulerCapacity(ctx context.Context, capacity SchedulerCapacity) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO scheduler_capacity (
		campaign_id, batch_id, queue, artifact, min_capacity, max_capacity, effective_capacity, recommended_capacity,
		running, pending, retry_waiting, stale_running, completed, failed, dead, avg_duration_ms, throughput_per_min,
		stat_requests, stat_results, stat_errors, error_rate_percent, last_decision, decision_reason, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8,
		$9, $10, $11, $12, $13, $14, $15, $16, $17,
		$18, $19, $20, $21, $22, $23, NOW()
	)
	ON CONFLICT (campaign_id, batch_id, queue) DO UPDATE SET
		artifact = EXCLUDED.artifact,
		min_capacity = EXCLUDED.min_capacity,
		max_capacity = EXCLUDED.max_capacity,
		effective_capacity = EXCLUDED.effective_capacity,
		recommended_capacity = EXCLUDED.recommended_capacity,
		running = EXCLUDED.running,
		pending = EXCLUDED.pending,
		retry_waiting = EXCLUDED.retry_waiting,
		stale_running = EXCLUDED.stale_running,
		completed = EXCLUDED.completed,
		failed = EXCLUDED.failed,
		dead = EXCLUDED.dead,
		avg_duration_ms = EXCLUDED.avg_duration_ms,
		throughput_per_min = EXCLUDED.throughput_per_min,
		stat_requests = EXCLUDED.stat_requests,
		stat_results = EXCLUDED.stat_results,
		stat_errors = EXCLUDED.stat_errors,
		error_rate_percent = EXCLUDED.error_rate_percent,
		last_decision = EXCLUDED.last_decision,
		decision_reason = EXCLUDED.decision_reason,
		updated_at = NOW()`,
		capacity.CampaignID, capacity.BatchID, capacity.Queue, capacity.Artifact, capacity.MinCapacity, capacity.MaxCapacity,
		capacity.EffectiveCapacity, capacity.RecommendedCapacity, capacity.Running, capacity.Pending, capacity.RetryWaiting,
		capacity.StalledRunning, capacity.Completed, capacity.Failed, capacity.Dead, capacity.AvgDurationMs, capacity.ThroughputPerMin,
		capacity.StatRequests, capacity.StatResults, capacity.StatErrors, capacity.ErrorRatePercent, capacity.LastDecision, capacity.DecisionReason)
	return err
}

func decideSchedulerCapacity(request SchedulerCapacityUpdateRequest, policy SchedulerCapacityPolicy, previous SchedulerCapacity, group WorkItemGroupSummary, stat ArtifactStatSummary) SchedulerCapacity {
	current := previous.EffectiveCapacity
	if current <= 0 {
		current = policy.Initial
	}
	if current <= 0 {
		current = policy.Min
	}
	current = clampInt(current, policy.Min, policy.Max)
	stalled := group.StalledRunning
	statErrorRate := percentage(stat.Errors, stat.Requests)
	workErrors := group.Failed + group.Dead
	workDone := group.Completed + group.Failed + group.Dead
	workErrorRate := percentageInt(workErrors, workDone)
	errorRate := maxFloat64(workErrorRate, statErrorRate)

	next := current
	decision := "hold"
	reason := "capacity stable"
	switch {
	case stalled > 0:
		next = maxInt(policy.Min, current/2)
		decision = "decrease"
		reason = "stalled running work detected"
	case errorRate >= float64(policy.ErrorLimit) && errorRate > 0:
		next = maxInt(policy.Min, current/2)
		decision = "decrease"
		reason = "recent error rate above policy"
	case policy.SlowMs > 0 && group.AvgDurationMs > policy.SlowMs && group.Running >= current:
		next = maxInt(policy.Min, current/2)
		decision = "decrease"
		reason = "average duration above policy while saturated"
	case group.Pending > 0 && group.RetryWaiting == 0 && group.Running >= current && current < policy.Max:
		next = current + 1
		decision = "increase"
		reason = "healthy backlog with saturated capacity"
	case group.Pending == 0 && group.Running == 0:
		next = maxInt(policy.Min, minInt(current, policy.Initial))
		decision = "cooldown"
		reason = "queue idle"
	}
	next = clampInt(next, policy.Min, policy.Max)
	return SchedulerCapacity{
		CampaignID:          request.CampaignID,
		BatchID:             request.BatchID,
		Queue:               policy.Queue,
		Artifact:            policy.Artifact,
		MinCapacity:         policy.Min,
		MaxCapacity:         policy.Max,
		EffectiveCapacity:   next,
		RecommendedCapacity: next,
		Running:             group.Running,
		Pending:             group.Pending,
		RetryWaiting:        group.RetryWaiting,
		StalledRunning:      stalled,
		Completed:           group.Completed,
		Failed:              group.Failed,
		Dead:                group.Dead,
		AvgDurationMs:       group.AvgDurationMs,
		ThroughputPerMin:    group.ThroughputPerMin,
		StatRequests:        stat.Requests,
		StatResults:         stat.Results,
		StatErrors:          stat.Errors,
		ErrorRatePercent:    errorRate,
		LastDecision:        decision,
		DecisionReason:      reason,
		UpdatedAt:           time.Now(),
	}
}

func defaultSchedulerCapacities(request SchedulerCapacityUpdateRequest) []SchedulerCapacity {
	policies := DefaultSchedulerCapacityPolicies()
	out := make([]SchedulerCapacity, 0, len(policies))
	for _, policy := range policies {
		out = append(out, SchedulerCapacity{
			CampaignID:          request.CampaignID,
			BatchID:             request.BatchID,
			SnapshotKind:        "capacity_controller_decision",
			Queue:               policy.Queue,
			Artifact:            policy.Artifact,
			MinCapacity:         policy.Min,
			MaxCapacity:         policy.Max,
			EffectiveCapacity:   policy.Initial,
			RecommendedCapacity: policy.Initial,
			LastDecision:        "initial",
			DecisionReason:      "default capacity policy",
			SnapshotNote:        "last scheduler capacity controller decision; runtime_queues is the live work_items state",
			UpdatedAt:           time.Now(),
		})
	}
	return out
}

func defaultCapacityForQueue(queue string) int {
	for _, policy := range DefaultSchedulerCapacityPolicies() {
		if policy.Queue == queue {
			return policy.Initial
		}
	}
	return 1
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func percentageInt(numerator, denominator int) float64 {
	if denominator <= 0 || numerator <= 0 {
		return 0
	}
	return float64(numerator) * 100 / float64(denominator)
}

func percentage(numerator, denominator int64) float64 {
	if denominator <= 0 || numerator <= 0 {
		return 0
	}
	return float64(numerator) * 100 / float64(denominator)
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
