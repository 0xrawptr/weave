package workflow

import (
	"strings"
	"testing"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
)

func TestSplitCIDRToPrefix(t *testing.T) {
	tests := []struct {
		name   string
		target string
		prefix int
		want   int
	}{
		{name: "slash 20 to slash 24", target: "10.0.0.0/20", prefix: 24, want: 16},
		{name: "slash 23 to slash 24", target: "10.0.0.0/23", prefix: 24, want: 2},
		{name: "slash 24 stays one chunk", target: "10.0.0.0/24", prefix: 24, want: 1},
		{name: "slash 27 stays one chunk", target: "10.0.0.0/27", prefix: 24, want: 1},
		{name: "plain ip stays one chunk", target: "10.0.0.1", prefix: 24, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCIDRToPrefix(tt.target, tt.prefix)
			if len(got) != tt.want {
				t.Fatalf("len(splitCIDRToPrefix(%q, %d)) = %d, want %d: %#v", tt.target, tt.prefix, len(got), tt.want, got)
			}
		})
	}
}

func TestBuildPortScanChunksDeduplicates(t *testing.T) {
	chunks := buildPortScanChunks([]string{
		"10.0.0.0/23",
		"10.0.0.0/24",
		"10.0.2.1",
	}, 24)
	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d, want 3: %#v", len(chunks), chunks)
	}
	if chunks[0].Chunk != "10.0.0.0/24" || chunks[1].Chunk != "10.0.1.0/24" || chunks[2].Chunk != "10.0.2.1" {
		t.Fatalf("unexpected chunks: %#v", chunks)
	}
}

func TestShouldRunDNSPreflight(t *testing.T) {
	tests := []struct {
		name  string
		chunk batchPortScanChunk
		want  bool
	}{
		{name: "domain", chunk: batchPortScanChunk{Target: "example.com", Chunk: "example.com"}, want: true},
		{name: "single ip", chunk: batchPortScanChunk{Target: "10.0.0.1", Chunk: "10.0.0.1"}, want: true},
		{name: "cidr", chunk: batchPortScanChunk{Target: "10.0.0.0/24", Chunk: "10.0.0.0/24"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRunDNSPreflight(tt.chunk); got != tt.want {
				t.Fatalf("shouldRunDNSPreflight(%#v) = %v, want %v", tt.chunk, got, tt.want)
			}
		})
	}
}

func TestDNSPreflightWorkItem(t *testing.T) {
	input := BatchPortScanInput{CampaignID: "camp-1", MaxAttempts: 2}
	chunk := batchPortScanChunk{Target: "example.com", Chunk: "example.com"}
	item := dnsPreflightWorkItem("batch-1", input, chunk, "", "pending", "", data.ScheduleNow)
	if item.Type != "dns_preflight" || item.Artifact != "dns_preflight" || item.Queue != "dns" {
		t.Fatalf("unexpected preflight item: %#v", item)
	}
	if item.Target != "example.com" || item.Schedule != data.ScheduleNow || item.MaxAttempts != 2 {
		t.Fatalf("unexpected preflight metadata: %#v", item)
	}
}

func TestSchedulePortScanChunks(t *testing.T) {
	chunks := buildPortScanChunks([]string{
		"10.0.0.0/23",
		"10.0.2.0/24",
	}, 24)
	got := schedulePortScanChunks(chunks, []string{"10.0.1.0/24"}, 24)
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3: %#v", len(got), got)
	}
	if got[0].Chunk != "10.0.1.0/24" {
		t.Fatalf("scheduled chunk was not first: %#v", got)
	}
	if got[1].Chunk != "10.0.0.0/24" || got[2].Chunk != "10.0.2.0/24" {
		t.Fatalf("batch order changed unexpectedly: %#v", got)
	}
}

func TestActionWorkItemFromDAGNode(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:              "camp-1",
			MaxAttempts:             2,
			PlannedDAGMaxIterations: 3,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-spray",
		Artifact: "spray",
		Target:   "10.0.0.0/24",
		Input:    map[string]any{"base_urls": []string{"http://10.0.0.1:8080"}, "wordlist_mode": "full"},
		Decision: planner.Decision{Schedule: data.ScheduleNow},
		Reason:   "expand attack surface",
		DedupKey: "dedup-spray-full",
	}

	item := actionWorkItemFromDAGNode(input, parent, node, 2, 3)
	if item.Type != "spray_shard" || item.Artifact != "spray" || item.Queue != "spray" {
		t.Fatalf("unexpected work item mapping: %#v", item)
	}
	if item.ParentID != parent.ID || item.Schedule != data.ScheduleNow || item.MaxAttempts != 2 {
		t.Fatalf("unexpected work item metadata: %#v", item)
	}

	parsed := parseSchedulerWorkItemInput(item)
	if parsed.Iteration != 2 || parsed.MaxIterations != 3 {
		t.Fatalf("missing replan iteration metadata: %#v", parsed)
	}
	if parsed.ActionInput["wordlist_mode"] != "full" {
		t.Fatalf("missing action input: %#v", parsed.ActionInput)
	}
	if parsed.DedupKey != "dedup-spray-full" {
		t.Fatalf("missing action dedup key: %#v", parsed)
	}
	action := scheduledPlannerAction(item, parsed, "child-workflow-1")
	if action.WorkflowID != "child-workflow-1" {
		t.Fatalf("missing action workflow id: %#v", action)
	}
	persistInput := action.PersistInput()
	meta, ok := persistInput["_planner"].(map[string]interface{})
	if !ok || meta["dedup_key"] != "dedup-spray-full" {
		t.Fatalf("expected persisted planner dedup key, got %#v", persistInput)
	}
}

func TestActionWorkItemUsesNowScheduleFromParentOrNode(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:  "camp-1",
			MaxAttempts: 1,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleNow}
	node := planner.DAGPlanNode{
		ID:       "node-fingers",
		Artifact: "fingers",
		Target:   "10.0.0.0/24",
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	item := actionWorkItemFromDAGNode(input, parent, node, 1, 2)
	if item.Schedule != data.ScheduleNow {
		t.Fatalf("schedule = %q, want now", item.Schedule)
	}
}

func TestPlannedDAGFollowUpWorkItemUsesSignalSchedule(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:              "camp-1",
			PlannedDAGMaxIterations: 2,
		},
	}
	parent := data.WorkItem{ID: "chunk-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}

	item := plannedDAGFollowUpWorkItemFromScheduler(input, parent, data.ScheduleNow)
	if item.Schedule != data.ScheduleNow {
		t.Fatalf("schedule = %q, want now", item.Schedule)
	}
	if item.ParentID != parent.ID || item.Target != parent.Target {
		t.Fatalf("unexpected follow-up item: %#v", item)
	}
}

func TestPlannerSignalSchedule(t *testing.T) {
	if got := plannerSignalSchedule(planner.AssetCondition{EventType: "changed"}); got != data.ScheduleNow {
		t.Fatalf("changed event schedule = %q, want now", got)
	}
	if got := plannerSignalSchedule(planner.AssetCondition{EventType: "new"}); got != data.ScheduleNow {
		t.Fatalf("new event schedule = %q, want now", got)
	}
	if got := plannerSignalSchedule(planner.AssetCondition{Type: "service", Status: "observed"}); got != data.ScheduleBatch {
		t.Fatalf("observed service schedule = %q, want batch", got)
	}
	if got := plannerSignalSchedule(planner.AssetCondition{Type: "fingerprint", Status: "observed"}); got != data.ScheduleNow {
		t.Fatalf("observed fingerprint schedule = %q, want now", got)
	}
	if got := plannerSignalSchedule(planner.AssetCondition{Type: "service", Status: "confirmed"}); got != data.ScheduleNow {
		t.Fatalf("confirmed service schedule = %q, want now", got)
	}
}

func TestSchedulerPhasePlansGateWorkItemTypes(t *testing.T) {
	tests := []struct {
		phase string
		want  []string
		now   bool
	}{
		{phase: CampaignPhaseBootstrap, want: []string{"dns_preflight"}},
		{phase: CampaignPhaseDiscovery, want: []string{"portscan_chunk", "planned_dag_followup", "fingers_action", "spray_shard"}},
		{phase: CampaignPhaseExpansion, want: []string{"spray_shard", "fingers_action"}},
		{phase: CampaignPhaseVerification, want: []string{"nuclei_group", "spray_shard"}},
		{phase: CampaignPhaseSteady, want: []string{"dns_preflight", "portscan_chunk", "planned_dag_followup", "fingers_action", "spray_shard", "nuclei_group"}, now: true},
	}
	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			plan := schedulerPhasePlanFor(tt.phase)
			if plan.NowOnly != tt.now {
				t.Fatalf("NowOnly = %v, want %v", plan.NowOnly, tt.now)
			}
			if len(plan.ItemTypes) != len(tt.want) {
				t.Fatalf("item types = %#v, want %#v", plan.ItemTypes, tt.want)
			}
			for i := range tt.want {
				if plan.ItemTypes[i] != tt.want[i] {
					t.Fatalf("item types = %#v, want %#v", plan.ItemTypes, tt.want)
				}
			}
		})
	}
}

func TestSchedulerPhasePrefersVerificationOverRunningSprayWhenVerificationQueued(t *testing.T) {
	snapshot := data.WorkItemProgressSummary{
		ByType: []data.WorkItemGroupSummary{
			{Key: "spray_shard", Running: 3},
			{Key: "nuclei_group", Pending: 21},
		},
	}
	if got := data.InferCampaignPhaseFromSummary(snapshot); got != CampaignPhaseVerification {
		t.Fatalf("phase = %q, want verification", got)
	}
}

func TestSchedulerPhaseTracksRunningSprayWork(t *testing.T) {
	snapshot := data.WorkItemProgressSummary{
		ByType: []data.WorkItemGroupSummary{
			{Key: "spray_shard", Running: 3},
		},
	}
	if got := data.InferCampaignPhaseFromSummary(snapshot); got != CampaignPhaseExpansion {
		t.Fatalf("phase = %q, want expansion", got)
	}
}

func TestScheduledBatchStatusCompletesWhenNoRunningWork(t *testing.T) {
	result := &SchedulerWorkflowResult{
		PortScanTotal:   10,
		PortScanDone:    10,
		PortScanRunning: 0,
	}
	if got := scheduledBatchStatus(result); got != "completed" {
		t.Fatalf("status = %q, want completed", got)
	}
}

func TestNormalizeCampaignPhase(t *testing.T) {
	tests := map[string]string{
		"":             CampaignPhaseAuto,
		"unknown":      CampaignPhaseAuto,
		"BOOTSTRAP":    CampaignPhaseBootstrap,
		"DISCOVERY":    CampaignPhaseDiscovery,
		" expansion ":  CampaignPhaseExpansion,
		"verification": CampaignPhaseVerification,
		"steady":       CampaignPhaseSteady,
	}
	for input, want := range tests {
		if got := data.NormalizeCampaignPhase(input); got != want {
			t.Fatalf("NormalizeCampaignPhase(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDesiredSchedulerCampaignPhaseUsesManualOverride(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchInput: BatchPortScanInput{CampaignPhase: CampaignPhaseVerification},
	}
	snapshot := data.WorkItemProgressSummary{
		ByType: []data.WorkItemGroupSummary{{Key: data.WorkItemTypeDNSPreflight, Pending: 1}},
	}
	phase, reason := desiredSchedulerCampaignPhaseFromSnapshot(input, snapshot)
	if phase != CampaignPhaseVerification || reason != "manual phase override" {
		t.Fatalf("phase, reason = %q, %q; want verification manual override", phase, reason)
	}
}

func TestSprayShardWorkItemsFromDAGNode(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:         "camp-1",
			MaxAttempts:        2,
			SprayShardBaseURLs: 1,
			SprayShardWords:    2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-spray",
		Artifact: "spray",
		Target:   "10.0.0.0/24",
		Input: map[string]any{
			"base_urls": []string{"http://10.0.0.1:8080", "http://10.0.0.2:8080"},
			"wordlist":  []string{"a", "b", "c"},
		},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	items := sprayShardWorkItemsFromDAGNode(input, parent, node, 1, 3)
	if len(items) != 4 {
		t.Fatalf("len(items) = %d, want 4: %#v", len(items), items)
	}
	for i, item := range items {
		if item.Type != "spray_shard" || item.Queue != "spray" || item.Artifact != "spray" {
			t.Fatalf("unexpected item %d: %#v", i, item)
		}
		parsed := parseSchedulerWorkItemInput(item)
		if parsed.ShardIndex != i+1 {
			t.Fatalf("shard index = %d, want %d", parsed.ShardIndex, i+1)
		}
		baseURLs := data.ActionInputStrings(parsed.ActionInput, "base_urls")
		if len(baseURLs) != 1 {
			t.Fatalf("base url shard size = %d, want 1: %#v", len(baseURLs), parsed.ActionInput)
		}
		words := data.ActionInputStrings(parsed.ActionInput, "wordlist")
		if len(words) == 0 || len(words) > 2 {
			t.Fatalf("word shard size = %d, want 1..2: %#v", len(words), parsed.ActionInput)
		}
	}
}

func TestFullSprayShardWorkItemsUseWordlistRanges(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:         "camp-1",
			MaxAttempts:        2,
			SprayShardBaseURLs: 1,
			SprayShardWords:    500,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-spray",
		Artifact: "spray",
		Target:   "10.0.0.0/24",
		Input: map[string]any{
			"base_urls":     []string{"http://10.0.0.1:8080"},
			"wordlist_mode": "full",
		},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	items := sprayShardWorkItemsFromDAGNode(input, parent, node, 1, 3)
	want := len(chunkWordlistRanges(len(artifact.FullSprayWordlist()), 500))
	if want == 0 {
		want = 1
	}
	if len(items) != want {
		t.Fatalf("len(items) = %d, want %d", len(items), want)
	}
	parsed := parseSchedulerWorkItemInput(items[0])
	if _, ok := parsed.ActionInput["wordlist"]; ok {
		t.Fatalf("full spray shard should not persist literal wordlist: %#v", parsed.ActionInput)
	}
	if parsed.ActionInput["wordlist_mode"] != "full" || parsed.ActionInput["wordlist_offset"] == nil || parsed.ActionInput["wordlist_limit"] == nil {
		t.Fatalf("missing full wordlist range metadata: %#v", parsed.ActionInput)
	}
}

func TestFullSprayShardWorkItemsUseSingleBaseURLChunks(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:         "camp-1",
			MaxAttempts:        2,
			SprayShardBaseURLs: 10,
			SprayShardWords:    500,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-spray",
		Artifact: "spray",
		Target:   "10.0.0.0/24",
		Input: map[string]any{
			"base_urls":     []string{"http://10.0.0.1:8080", "http://10.0.0.2:8080"},
			"wordlist_mode": "full",
		},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	items := sprayShardWorkItemsFromDAGNode(input, parent, node, 1, 3)
	wantPerURL := len(chunkWordlistRanges(len(artifact.FullSprayWordlist()), 500))
	if wantPerURL == 0 {
		wantPerURL = 1
	}
	if len(items) != wantPerURL*2 {
		t.Fatalf("len(items) = %d, want %d", len(items), wantPerURL*2)
	}
	for _, item := range items {
		parsed := parseSchedulerWorkItemInput(item)
		baseURLs := data.ActionInputStrings(parsed.ActionInput, "base_urls")
		if len(baseURLs) != 1 {
			t.Fatalf("full spray shard must contain one base URL, got %#v", parsed.ActionInput)
		}
	}
}

func TestSprayShardWorkItemsSkipEmptyInput(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:  "camp-1",
			MaxAttempts: 2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "115.236.38.192/26", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-empty-spray",
		Artifact: "spray",
		Target:   "115.236.38.192/26",
		Input:    map[string]any{},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	if items := sprayShardWorkItemsFromDAGNode(input, parent, node, 1, 3); len(items) != 0 {
		t.Fatalf("empty spray input created work items: %#v", items)
	}
}

func TestActionWorkItemsFromDAGNodeUsesSharderRegistry(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:  "camp-1",
			MaxAttempts: 2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "115.236.38.192/26", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-empty-spray",
		Artifact: "spray",
		Target:   "115.236.38.192/26",
		Input:    map[string]any{},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}

	if items := actionWorkItemsFromDAGNode(input, parent, node, 1, 3); len(items) != 0 {
		t.Fatalf("registry sharder created empty spray work items: %#v", items)
	}
}

func TestCIDRWithoutHTTPDoesNotCreateSprayShardWork(t *testing.T) {
	target := "115.236.38.192/26"
	actions := planner.PlanFromState(planner.State{
		Target:     target,
		CampaignID: "camp-1",
	})
	for _, action := range actions {
		if action.Artifact == "spray" {
			t.Fatalf("CIDR without HTTP services created spray action: %#v", actions)
		}
	}

	plan := planner.PlanDAGFromActions(target, "camp-1", actions)
	for _, node := range plan.Nodes {
		if node.Artifact == "spray" {
			t.Fatalf("CIDR without HTTP services created spray DAG node: %#v", plan.Nodes)
		}
	}

	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:  "camp-1",
			MaxAttempts: 2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: target, Schedule: data.ScheduleBatch}
	var items []data.WorkItem
	for _, node := range plan.Nodes {
		items = append(items, actionWorkItemsFromDAGNode(input, parent, node, 1, 3)...)
	}
	for _, item := range items {
		if item.Type == data.WorkItemTypeSprayShard || item.Artifact == "spray" || item.Queue == "spray" {
			t.Fatalf("CIDR without HTTP services materialized spray work item: %#v", item)
		}
	}
}

func TestInvalidSprayActionDoesNotReachPendingWorkItem(t *testing.T) {
	target := "115.236.38.192/26"
	plan := planner.PlanDAGFromActions(target, "camp-1", []planner.Action{{
		ID:       "spray-empty",
		Target:   target,
		Artifact: "spray",
		Input:    map[string]interface{}{},
	}})
	if len(plan.Nodes) != 0 || len(plan.Actions) != 0 {
		t.Fatalf("invalid spray action reached DAG: nodes=%#v actions=%#v", plan.Nodes, plan.Actions)
	}

	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:  "camp-1",
			MaxAttempts: 2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: target, Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-empty-spray",
		Artifact: "spray",
		Target:   target,
		Input:    map[string]any{},
		Decision: planner.Decision{Schedule: data.ScheduleBatch},
	}
	if items := actionWorkItemsFromDAGNode(input, parent, node, 1, 3); len(items) != 0 {
		t.Fatalf("empty spray DAG node reached pending work item: %#v", items)
	}
}

func TestArtifactWorkItemChildWorkflowIDIsStablePerAttempt(t *testing.T) {
	target := "202.205.161.0/24"
	first := artifactWorkItemChildWorkflowID("batch-1", "spray_shard", target, "item-a", 1)
	second := artifactWorkItemChildWorkflowID("batch-1", "spray_shard", target, "item-b", 1)
	if first == second {
		t.Fatalf("child workflow IDs should be unique per work item: %q", first)
	}
	if !strings.Contains(first, "item-a") || !strings.Contains(second, "item-b") {
		t.Fatalf("child workflow IDs should include work item IDs: first=%q second=%q", first, second)
	}
	third := artifactWorkItemChildWorkflowID("batch-1", "spray_shard", target, "item-a", 1)
	if first != third {
		t.Fatalf("child workflow IDs should be stable across scheduler runs: first=%q third=%q", first, third)
	}
	retry := artifactWorkItemChildWorkflowID("batch-1", "spray_shard", target, "item-a", 2)
	if first == retry {
		t.Fatalf("child workflow IDs should change per attempt: first=%q retry=%q", first, retry)
	}
}

func TestChunkWorkItems(t *testing.T) {
	items := []data.WorkItem{
		{ID: "a"},
		{ID: "b"},
		{ID: "c"},
		{ID: "d"},
		{ID: "e"},
	}
	chunks := chunkWorkItems(items, 2)
	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d, want 3: %#v", len(chunks), chunks)
	}
	if len(chunks[0]) != 2 || len(chunks[1]) != 2 || len(chunks[2]) != 1 {
		t.Fatalf("unexpected chunk sizes: %#v", chunks)
	}
	if chunks[2][0].ID != "e" {
		t.Fatalf("unexpected final chunk: %#v", chunks[2])
	}
}

func TestSchedulerBurstUsesRemainingButCapacityRemainsSeparate(t *testing.T) {
	capacity := schedulerCapacityMap{"portscan": 4}
	if got := schedulerPipelineBurst(capacity, "portscan", 1); got != 1 {
		t.Fatalf("schedulerPipelineBurst = %d, want remaining-limited start budget 1", got)
	}
	if got := schedulerQueueCapacity(capacity, "portscan"); got != 4 {
		t.Fatalf("schedulerQueueCapacity = %d, want full queue capacity 4", got)
	}
}

func TestSchedulerQueueCapacityDefaultsToOne(t *testing.T) {
	if got := schedulerPipelineBurst(schedulerCapacityMap{}, "missing", 10); got != 1 {
		t.Fatalf("schedulerPipelineBurst default = %d, want 1", got)
	}
	if got := schedulerQueueCapacity(schedulerCapacityMap{"dns": 0}, "dns"); got != 1 {
		t.Fatalf("schedulerQueueCapacity default = %d, want 1", got)
	}
}

func TestChunkStringsTrimsBeforeDedup(t *testing.T) {
	chunks := data.ChunkStrings([]string{" a ", "a", "", " b "}, 10, true)
	if len(chunks) != 1 {
		t.Fatalf("len(chunks) = %d, want 1: %#v", len(chunks), chunks)
	}
	if len(chunks[0]) != 2 || chunks[0][0] != "a" || chunks[0][1] != "b" {
		t.Fatalf("ChunkStrings = %#v, want trimmed unique values", chunks)
	}
}

func TestNucleiGroupWorkItemsFromDAGNode(t *testing.T) {
	input := SchedulerWorkflowInput{
		BatchID: "batch-1",
		BatchInput: BatchPortScanInput{
			CampaignID:           "camp-1",
			MaxAttempts:          1,
			NucleiGroupTargets:   2,
			NucleiGroupTemplates: 2,
		},
	}
	parent := data.WorkItem{ID: "parent-1", Target: "10.0.0.0/24", Schedule: data.ScheduleBatch}
	node := planner.DAGPlanNode{
		ID:       "node-nuclei",
		Artifact: "nuclei",
		Target:   "10.0.0.0/24",
		Input: map[string]any{
			"targets": []string{"http://a", "http://b", "http://c"},
			"ids":     []string{"tpl-1", "tpl-2", "tpl-3"},
		},
		Decision: planner.Decision{Schedule: data.ScheduleNow},
	}

	items := nucleiGroupWorkItemsFromDAGNode(input, parent, node, 1, 3)
	if len(items) != 4 {
		t.Fatalf("len(items) = %d, want 4: %#v", len(items), items)
	}
	for i, item := range items {
		if item.Type != "nuclei_group" || item.Queue != "nuclei" || item.Artifact != "nuclei" {
			t.Fatalf("unexpected item %d: %#v", i, item)
		}
		parsed := parseSchedulerWorkItemInput(item)
		if parsed.ShardIndex != i+1 {
			t.Fatalf("shard index = %d, want %d", parsed.ShardIndex, i+1)
		}
		targets := data.ActionInputStrings(parsed.ActionInput, "targets")
		ids := data.ActionInputStrings(parsed.ActionInput, "ids")
		if len(targets) == 0 || len(targets) > 2 {
			t.Fatalf("target group size = %d, want 1..2: %#v", len(targets), parsed.ActionInput)
		}
		if len(ids) == 0 || len(ids) > 2 {
			t.Fatalf("template group size = %d, want 1..2: %#v", len(ids), parsed.ActionInput)
		}
	}
}

func TestIsNoopArtifactAction(t *testing.T) {
	if !isNoopArtifactAction("nuclei", `cause="No templates available"`, nil) {
		t.Fatalf("expected nuclei no-template error to be noop")
	}
	if !isNoopArtifactAction("nuclei", "", []byte(`{"total":0,"skipped_reason":"no_templates_available"}`)) {
		t.Fatalf("expected nuclei skipped_reason output to be noop")
	}
	if isNoopArtifactAction("nuclei", "", []byte(`{"total":0}`)) {
		t.Fatalf("zero findings with templates should not be noop")
	}
	if isNoopArtifactAction("spray", `cause="No templates available"`, nil) {
		t.Fatalf("only nuclei no-template should be noop")
	}
}
