package workflow

import "testing"

func TestNormalizeDAGNodes(t *testing.T) {
	nodes, err := normalizeDAGNodes("example.com", []DAGNode{
		{Artifact: "gogo", Input: map[string]interface{}{"ports": "top1000"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d", len(nodes))
	}
	if nodes[0].ID != "node-0001" {
		t.Fatalf("default ID = %q", nodes[0].ID)
	}
	if nodes[0].Target != "example.com" {
		t.Fatalf("target = %q", nodes[0].Target)
	}
	if nodes[0].Priority != 50 {
		t.Fatalf("priority = %d", nodes[0].Priority)
	}
}

func TestNormalizeDAGNodesRejectsDuplicateIDs(t *testing.T) {
	_, err := normalizeDAGNodes("example.com", []DAGNode{
		{ID: "scan", Artifact: "gogo"},
		{ID: "scan", Artifact: "fingers"},
	})
	if err == nil {
		t.Fatal("expected duplicate ID error")
	}
}

func TestReadyDAGNodes(t *testing.T) {
	nodes := []DAGNode{
		{ID: "gogo", Artifact: "gogo", Priority: 10},
		{ID: "fingers", Artifact: "fingers", DependsOn: []string{"gogo"}, Priority: 80},
		{ID: "cdn", Artifact: "cdncheck", Priority: 20},
	}
	status := map[string]string{
		"gogo":    dagStatusPending,
		"fingers": dagStatusPending,
		"cdn":     dagStatusPending,
	}
	ready := readyDAGNodes(status, nodes)
	if len(ready) != 2 {
		t.Fatalf("len(ready) = %d", len(ready))
	}
	if ready[0].ID != "cdn" || ready[1].ID != "gogo" {
		t.Fatalf("unexpected ready order: %#v", ready)
	}

	status["gogo"] = dagStatusCompleted
	ready = readyDAGNodes(status, nodes)
	if len(ready) != 2 || ready[0].ID != "fingers" {
		t.Fatalf("expected fingers to become highest-priority ready node: %#v", ready)
	}
}

func TestMarkBlockedDAGNodes(t *testing.T) {
	nodes := map[string]DAGNode{
		"gogo":    {ID: "gogo", Artifact: "gogo"},
		"fingers": {ID: "fingers", Artifact: "fingers", DependsOn: []string{"gogo"}},
		"nuclei":  {ID: "nuclei", Artifact: "nuclei", DependsOn: []string{"fingers"}},
	}
	status := map[string]string{
		"gogo":    dagStatusFailed,
		"fingers": dagStatusPending,
		"nuclei":  dagStatusPending,
	}
	skipped := markBlockedDAGNodes(status, nodes)
	if len(skipped) != 2 {
		t.Fatalf("len(skipped) = %d, want 2", len(skipped))
	}
	if status["fingers"] != dagStatusSkipped || status["nuclei"] != dagStatusSkipped {
		t.Fatalf("dependent nodes were not skipped: %#v", status)
	}
}
