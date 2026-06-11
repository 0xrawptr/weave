package etl

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0xrawptr/weave/internal/data"
)

func gogoJSON(items ...map[string]interface{}) []byte {
	out := map[string]interface{}{"results": items}
	b, _ := json.Marshal(out)
	return b
}

func TestGogoExtractor(t *testing.T) {
	e := &GogoExtractor{}

	raw := gogoJSON(
		map[string]interface{}{
			"ip": "192.168.1.1", "port": "22", "protocol": "tcp",
			"frameworks": map[string]interface{}{"ssh": map[string]interface{}{"name": "ssh"}},
		},
		map[string]interface{}{
			"ip": "192.168.1.1", "port": "80", "protocol": "http",
			"frameworks": map[string]interface{}{"nginx": map[string]interface{}{"name": "nginx"}},
		},
		map[string]interface{}{
			"ip": "192.168.1.2", "port": "443", "protocol": "https",
		},
	)

	result, err := e.Extract(context.Background(), "192.168.1.0/24", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}

	// Entity counts: 2 IPs + 3 ports + 3 services + 2 fingerprints = 10.
	if len(result.Entities) != 10 {
		t.Errorf("expected 10 entities, got %d", len(result.Entities))
	}

	// Relation counts: 3 has_port + 3 runs + 2 has_fingerprint = 8.
	if len(result.Relations) != 8 {
		t.Errorf("expected 8 relations, got %d", len(result.Relations))
	}

	// Verify relation directions.
	targetID := data.TargetID("192.168.1.0/24")
	ip1ID := data.GenerateID("ip", "192.168.1.0/24", "192.168.1.1")
	port22ID := data.GenerateID("port", "192.168.1.0/24", "192.168.1.1", "22")

	// Check IP → has_port → port direction.
	for _, rel := range result.Relations {
		if rel.Type == "has_port" && rel.FromID == ip1ID && rel.ToID == port22ID {
			goto ok
		}
	}
	t.Errorf("missing relation: ip(%s) → has_port → port(%s)", ip1ID[:8], port22ID[:8])
ok:

	_ = targetID // used
}

func TestGogoExtractorEmpty(t *testing.T) {
	e := &GogoExtractor{}
	result, err := e.Extract(context.Background(), "", gogoJSON())
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if result != nil && len(result.Entities) > 0 {
		t.Errorf("expected empty entities, got %d", len(result.Entities))
	}
}
func TestGogoExtractorNil(t *testing.T) {
	e := &GogoExtractor{}
	result, err := e.Extract(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for nil input")
	}
}

func TestFingersExtractor(t *testing.T) {
	e := &FingersExtractor{}
	raw, _ := json.Marshal(map[string]interface{}{
		"frameworks": []map[string]interface{}{
			{"name": "tomcat", "product": "Apache Tomcat", "version": "9.0.0"},
			{"name": "nginx", "product": "nginx", "version": "1.24.0"},
		},
		"count": 2,
	})

	result, err := e.Extract(context.Background(), "scan", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Entities) != 2 {
		t.Errorf("expected 2 entities, got %d", len(result.Entities))
	}
	if result.Entities[0].Source != "fingers" {
		t.Errorf("expected source=fingers, got %s", result.Entities[0].Source)
	}
}

func TestNucleiExtractor(t *testing.T) {
	e := &NucleiExtractor{}
	raw, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{"template_id": "CVE-2024-001", "info": "Test Vuln", "severity": "high", "target": "https://example.com"},
		},
		"total": 1,
	})

	result, err := e.Extract(context.Background(), "scan", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Entities) != 4 {
		t.Errorf("expected 4 entities, got %d", len(result.Entities))
	}
	if len(result.Relations) != 4 {
		t.Errorf("expected 4 relations, got %d", len(result.Relations))
	}
	if !hasEntityType(result.Entities, "vulnerability") {
		t.Errorf("expected vulnerability entity, got %#v", result.Entities)
	}
	if !hasEntityType(result.Entities, "url") {
		t.Errorf("expected url entity, got %#v", result.Entities)
	}
	if !hasEntityType(result.Entities, "template") {
		t.Errorf("expected template entity, got %#v", result.Entities)
	}
	if !hasEntityType(result.Entities, "cve") {
		t.Errorf("expected cve entity, got %#v", result.Entities)
	}
}

func hasEntityType(entities []Entity, entityType string) bool {
	for _, entity := range entities {
		if entity.Type == entityType {
			return true
		}
	}
	return false
}
