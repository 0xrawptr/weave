package admission

import (
	"encoding/json"
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

func TestAdmitRejectsOutOfScopeURL(t *testing.T) {
	item := testWorkItem("a", "spray", map[string]interface{}{
		"base_urls": []string{"https://cdn.example.net/app.js"},
	})
	result := Admit(Request{ScopeTargets: []string{"example.com"}, Items: []data.WorkItem{item}})
	if len(result.Admitted) != 0 {
		t.Fatalf("out-of-scope item admitted: %#v", result.Admitted)
	}
	if result.Decisions[0].Status != StatusRejected {
		t.Fatalf("status = %q, want rejected", result.Decisions[0].Status)
	}
}

func TestAdmitAllowsFirstPartySubdomain(t *testing.T) {
	item := testWorkItem("a", "spray", map[string]interface{}{
		"base_urls": []string{"https://api.example.com/login"},
	})
	result := Admit(Request{ScopeTargets: []string{"example.com"}, Items: []data.WorkItem{item}})
	if len(result.Admitted) != 1 {
		t.Fatalf("first-party item not admitted: %#v", result.Decisions)
	}
}

func TestAdmitAllowsLoopbackOnlyWhenInScope(t *testing.T) {
	item := testWorkItem("a", "spray", map[string]interface{}{
		"base_urls": []string{"http://127.0.0.1:8080"},
	})
	if got := Admit(Request{ScopeTargets: []string{"example.com"}, Items: []data.WorkItem{item}}); len(got.Admitted) != 0 {
		t.Fatalf("loopback should be rejected when not in scope")
	}
	if got := Admit(Request{ScopeTargets: []string{"127.0.0.1"}, Items: []data.WorkItem{item}}); len(got.Admitted) != 1 {
		t.Fatalf("loopback should be admitted when explicitly in scope: %#v", got.Decisions)
	}
}

func TestAdmitDoesNotDedupShardsBySharedDedupKey(t *testing.T) {
	first := testWorkItem("shard-1", "spray", map[string]interface{}{"base_urls": []string{"http://10.0.0.1:8080"}})
	first.Input = testEnvelope(map[string]interface{}{"base_urls": []string{"http://10.0.0.1:8080"}}, "same-action", 1)
	second := testWorkItem("shard-2", "spray", map[string]interface{}{"base_urls": []string{"http://10.0.0.1:8080"}})
	second.Input = testEnvelope(map[string]interface{}{"base_urls": []string{"http://10.0.0.1:8080"}}, "same-action", 2)
	result := Admit(Request{ScopeTargets: []string{"10.0.0.0/24"}, Items: []data.WorkItem{first, second}})
	if len(result.Admitted) != 2 {
		t.Fatalf("shared dedup-key shards should both be admitted: %#v", result.Decisions)
	}
}

func TestAdmitSkipsExistingPendingItem(t *testing.T) {
	item := testWorkItem("same-id", "fingers", map[string]interface{}{"urls": []string{"http://10.0.0.1:8080"}})
	existing := item
	existing.Status = data.WorkItemStatusPending
	result := Admit(Request{ScopeTargets: []string{"10.0.0.0/24"}, Items: []data.WorkItem{item}, Existing: []data.WorkItem{existing}})
	if len(result.Admitted) != 0 {
		t.Fatalf("duplicate pending item admitted")
	}
	if result.Decisions[0].Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Decisions[0].Status)
	}
}

func TestAdmitRequiresApprovalForDangerousActions(t *testing.T) {
	item := testWorkItem("zombie", "zombie", map[string]interface{}{"mode": "login_bruteforce"})
	result := Admit(Request{ScopeTargets: []string{"10.0.0.0/24"}, Items: []data.WorkItem{item}})
	if len(result.Admitted) != 0 {
		t.Fatalf("dangerous item admitted")
	}
	if result.Decisions[0].Status != StatusApprovalRequired {
		t.Fatalf("status = %q, want approval_required", result.Decisions[0].Status)
	}
}

func TestAdmitSkipsNoise(t *testing.T) {
	item := testWorkItem("noise", "spray", map[string]interface{}{"valid": false, "fuzzy": true})
	result := Admit(Request{ScopeTargets: []string{"10.0.0.0/24"}, Items: []data.WorkItem{item}})
	if len(result.Admitted) != 0 {
		t.Fatalf("noise item admitted")
	}
	if result.Decisions[0].Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Decisions[0].Status)
	}
}

func testWorkItem(id, artifact string, input map[string]interface{}) data.WorkItem {
	return data.WorkItem{
		ID:         id,
		CampaignID: "camp-1",
		BatchID:    "batch-1",
		Type:       artifact + "_action",
		Target:     "10.0.0.1",
		Artifact:   artifact,
		Status:     data.WorkItemStatusPending,
		Input:      testEnvelope(input, "dedup-"+id, 0),
	}
}

func testEnvelope(input map[string]interface{}, dedupKey string, shard int) []byte {
	raw, _ := json.Marshal(map[string]interface{}{
		"target":      "10.0.0.1",
		"input":       input,
		"dedup_key":   dedupKey,
		"shard_index": shard,
	})
	return raw
}
