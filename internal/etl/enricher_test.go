package etl

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/knowledge"
)

func TestKnowledgeEnricherAddsTemplatesTagsAndCVEs(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: CVE-2020-14882
info:
  name: Oracle WebLogic Server Console RCE
  severity: critical
  tags: cve,weblogic,rce
  classification:
    cve-id: CVE-2020-14882
`)
	if err := os.WriteFile(filepath.Join(dir, "weblogic.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}
	idx, err := knowledge.Load(knowledge.Options{NucleiTemplatesPath: dir})
	if err != nil {
		t.Fatalf("load knowledge: %v", err)
	}

	targetID := data.TargetID("example.com")
	result := &ExtractResult{
		Entities: []Entity{{
			ID:       data.GenerateID("fingerprint", "example.com", "weblogic"),
			Type:     "fingerprint",
			Value:    "weblogic",
			Source:   "test",
			TargetID: targetID,
		}},
	}
	enriched, err := NewKnowledgeEnricher(idx).Enrich(context.Background(), result)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	entity := enriched.Entities[0]
	if !has(entity.TemplateIDs, "CVE-2020-14882") {
		t.Fatalf("missing template ID: %#v", entity.TemplateIDs)
	}
	if !has(entity.CVEs, "CVE-2020-14882") {
		t.Fatalf("missing CVE: %#v", entity.CVEs)
	}
	if !has(entity.Tags, "weblogic") {
		t.Fatalf("missing tag: %#v", entity.Tags)
	}
}

func TestKnowledgeEnricherAddsCVEIntel(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: CVE-2020-14882
info:
  name: Oracle WebLogic Server Console RCE
  severity: critical
  tags: weblogic
  classification:
    cve-id: CVE-2020-14882
`)
	if err := os.WriteFile(filepath.Join(dir, "weblogic.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}
	kev := []byte(`{"vulnerabilities":[{"cveID":"CVE-2020-14882","vendorProject":"Oracle","product":"WebLogic Server"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), kev, 0644); err != nil {
		t.Fatal(err)
	}
	epss := []byte("cve,epss,percentile\nCVE-2020-14882,0.9,0.99\n")
	if err := os.WriteFile(filepath.Join(dir, "epss.csv"), epss, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := knowledge.Load(knowledge.Options{
		NucleiTemplatesPath: dir,
		KEVPath:             filepath.Join(dir, "kev.json"),
		EPSSPath:            filepath.Join(dir, "epss.csv"),
	})
	if err != nil {
		t.Fatalf("load knowledge: %v", err)
	}

	result := &ExtractResult{
		Entities: []Entity{{
			ID:    data.GenerateID("fingerprint", "example.com", "weblogic"),
			Type:  "fingerprint",
			Value: "weblogic",
		}},
	}
	enriched, err := NewKnowledgeEnricher(idx).Enrich(context.Background(), result)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	intel := enriched.Entities[0].CVEIntel
	if len(intel) != 1 {
		t.Fatalf("expected one cve intel item, got %#v", intel)
	}
	if !intel[0].KEV || intel[0].EPSS != 0.9 || intel[0].EPSSPercentile != 0.99 {
		t.Fatalf("unexpected cve intel: %#v", intel[0])
	}
}

func TestKnowledgeEnricherPassesVulnrichmentFields(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: CVE-2023-0001
info:
  name: Example Product RCE
  severity: critical
  tags: example-product
  classification:
    cve-id: CVE-2023-0001
`)
	if err := os.WriteFile(filepath.Join(dir, "template.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}
	vuln := []byte(`{
  "cveMetadata": {"cveId": "CVE-2023-0001"},
  "containers": {
    "cna": {
      "affected": [{"vendor": "Example", "product": "Example Product", "cpes": ["cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*"]}],
      "problemTypes": [{"descriptions": [{"cweId": "CWE-787"}]}],
      "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/test"}}]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(dir, "CVE-2023-0001.json"), vuln, 0644); err != nil {
		t.Fatal(err)
	}
	idx, err := knowledge.Load(knowledge.Options{
		NucleiTemplatesPath: dir,
		VulnrichmentPath:    filepath.Join(dir, "CVE-2023-0001.json"),
	})
	if err != nil {
		t.Fatalf("load knowledge: %v", err)
	}

	result := &ExtractResult{Entities: []Entity{{Type: "fingerprint", Value: "example-product"}}}
	enriched, err := NewKnowledgeEnricher(idx).Enrich(context.Background(), result)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	intel := enriched.Entities[0].CVEIntel
	if len(intel) != 1 {
		t.Fatalf("expected one cve intel item, got %#v", intel)
	}
	if intel[0].CVSSScore != 9.8 || !has(intel[0].CWEs, "CWE-787") || !has(intel[0].CPEs, "cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*") {
		t.Fatalf("unexpected vulnrichment fields: %#v", intel[0])
	}
}

func TestKnowledgeEnricherUsesEntityProduct(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: CVE-2020-14882
info:
  name: Oracle WebLogic Server Console RCE
  severity: critical
  classification:
    cve-id: CVE-2020-14882
`)
	if err := os.WriteFile(filepath.Join(dir, "template.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}
	vuln := []byte(`{
  "cveMetadata": {"cveId": "CVE-2020-14882"},
  "containers": {
    "cna": {
      "affected": [{"vendor": "Oracle", "product": "WebLogic Server", "cpes": ["cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*"]}],
      "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(dir, "CVE-2020-14882.json"), vuln, 0644); err != nil {
		t.Fatal(err)
	}
	idx, err := knowledge.Load(knowledge.Options{
		NucleiTemplatesPath: dir,
		VulnrichmentPath:    filepath.Join(dir, "CVE-2020-14882.json"),
	})
	if err != nil {
		t.Fatalf("load knowledge: %v", err)
	}

	result := &ExtractResult{Entities: []Entity{{
		Type:    "fingerprint",
		Value:   "unknown-fingerprint",
		Product: "WebLogic Server",
	}}}
	enriched, err := NewKnowledgeEnricher(idx).Enrich(context.Background(), result)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	entity := enriched.Entities[0]
	if entity.Product != "Oracle WebLogic Server" && entity.Product != "WebLogic Server" {
		t.Fatalf("expected product to be preserved or canonicalized, got %q", entity.Product)
	}
	if !has(entity.TemplateIDs, "CVE-2020-14882") {
		t.Fatalf("missing template ID from product lookup: %#v", entity.TemplateIDs)
	}
	if !has(entity.CPEs, "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*") {
		t.Fatalf("missing CPE from product lookup: %#v", entity.CPEs)
	}
}

func has(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
