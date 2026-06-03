package etl

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSprayExtractor(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{"url": "https://example.com/admin", "status_code": 200},
			{"url": "https://example.com/missing", "status_code": 404},
		},
		"total": 2,
	})
	result, err := (&SprayExtractor{}).Extract(context.Background(), "example.com", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(result.Entities) != 2 {
		t.Fatalf("expected 2 URL entities, got %d", len(result.Entities))
	}
	if !hasEntityType(result.Entities, "url") {
		t.Fatalf("expected url entity, got %#v", result.Entities)
	}
	admin := findEntity(result.Entities, "url", "https://example.com/admin")
	if admin == nil || admin.Priority < 60 {
		t.Fatalf("expected high-value admin URL priority, got %#v", admin)
	}
}

func TestZombieExtractor(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{"address": "10.0.0.1:22", "service": "ssh", "username": "root", "password": "toor"},
		},
		"total": 1,
	})
	result, err := (&ZombieExtractor{}).Extract(context.Background(), "10.0.0.1", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !hasEntityType(result.Entities, "credential") {
		t.Fatalf("expected credential entity, got %#v", result.Entities)
	}
	if !hasRelationType(result.Relations, RelHasCredential) {
		t.Fatalf("expected %s relation, got %#v", RelHasCredential, result.Relations)
	}
}

func TestCdncheckExtractor(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"is_cdn":   true,
		"is_cloud": false,
		"is_waf":   true,
		"cdn_name": "cloudflare",
		"ips":      []string{"1.1.1.1"},
	})
	result, err := (&CdncheckExtractor{}).Extract(context.Background(), "example.com", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !hasEntityType(result.Entities, "domain") || !hasEntityType(result.Entities, "ip") || !hasEntityType(result.Entities, "protection") {
		t.Fatalf("expected domain, ip and protection entities, got %#v", result.Entities)
	}
	if !hasRelationType(result.Relations, RelResolvesTo) {
		t.Fatalf("expected %s relation, got %#v", RelResolvesTo, result.Relations)
	}
	if !hasRelationType(result.Relations, RelProtectedBy) {
		t.Fatalf("expected %s relation, got %#v", RelProtectedBy, result.Relations)
	}
}

func TestNeutronExtractor(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{"template_id": "poc-test", "info": "Test Finding", "severity": "medium", "target": "https://example.com"},
		},
		"total": 1,
	})
	result, err := (&NeutronExtractor{}).Extract(context.Background(), "example.com", raw)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !hasEntityType(result.Entities, "vulnerability") || !hasEntityType(result.Entities, "template") || !hasEntityType(result.Entities, "url") {
		t.Fatalf("expected vulnerability, template and url entities, got %#v", result.Entities)
	}
	if !hasRelationType(result.Relations, RelDetects) {
		t.Fatalf("expected %s relation, got %#v", RelDetects, result.Relations)
	}
}

func TestNewRelationTypesAreValid(t *testing.T) {
	for _, relType := range []string{
		RelIdentifiesProduct,
		RelHasVersion,
		RelAffectedBy,
		RelHasTemplate,
		RelHasIntel,
		RelHasCPE,
		RelHasCWE,
		RelHasCredential,
		RelProtectedBy,
	} {
		if !ValidRelation(relType) {
			t.Fatalf("expected relation %q to be valid", relType)
		}
	}
}

func TestTemplateMatchesCVE(t *testing.T) {
	if !templateMatchesCVE("CVE-2022-0543", "CVE-2022-0543") {
		t.Fatalf("expected exact CVE template match")
	}
	if !templateMatchesCVE("redis-cve-2022-0543-rce", "CVE-2022-0543") {
		t.Fatalf("expected embedded CVE template match")
	}
	if templateMatchesCVE("exposed-redis", "CVE-2022-0543") {
		t.Fatalf("generic product template should not be linked as CVE evidence")
	}
}

func hasRelationType(relations []Relation, relType string) bool {
	for _, relation := range relations {
		if relation.Type == relType {
			return true
		}
	}
	return false
}

func findEntity(entities []Entity, entityType, value string) *Entity {
	for i := range entities {
		if entities[i].Type == entityType && entities[i].Value == value {
			return &entities[i]
		}
	}
	return nil
}
