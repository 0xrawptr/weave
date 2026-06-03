package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookupProductFromNucleiTemplates(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: CVE-2020-14882
info:
  name: Oracle WebLogic Server Console RCE
  severity: critical
  tags: cve,cve2020,weblogic,oracle,rce
  classification:
    cve-id: CVE-2020-14882
    cpe: cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*
`)
	if err := os.WriteFile(filepath.Join(dir, "weblogic.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{NucleiTemplatesPath: dir})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("weblogic")
	if len(got.TemplateIDs) != 1 || got.TemplateIDs[0] != "CVE-2020-14882" {
		t.Fatalf("unexpected template IDs: %#v", got.TemplateIDs)
	}
	if len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2020-14882" {
		t.Fatalf("unexpected CVEs: %#v", got.CVEs)
	}
	if !contains(got.Tags, "weblogic") {
		t.Fatalf("expected weblogic tag, got %#v", got.Tags)
	}
}

func TestLookupProductIncludesKEVAndEPSS(t *testing.T) {
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
	kev := []byte(`{
  "vulnerabilities": [
    {
      "cveID": "CVE-2020-14882",
      "vendorProject": "Oracle",
      "product": "WebLogic Server",
      "vulnerabilityName": "Oracle WebLogic Server RCE",
      "dateAdded": "2021-11-03",
      "dueDate": "2022-05-03",
      "knownRansomwareCampaignUse": "Known",
      "requiredAction": "Apply updates"
    }
  ]
}`)
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), kev, 0644); err != nil {
		t.Fatal(err)
	}
	epss := []byte(`#model_version:v2024.01.01
cve,epss,percentile
CVE-2020-14882,0.94412,0.99891
`)
	if err := os.WriteFile(filepath.Join(dir, "epss.csv"), epss, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{
		NucleiTemplatesPath: dir,
		KEVPath:             filepath.Join(dir, "kev.json"),
		EPSSPath:            filepath.Join(dir, "epss.csv"),
	})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("weblogic")
	if len(got.CVEIntel) != 1 {
		t.Fatalf("expected one cve intel item, got %#v", got.CVEIntel)
	}
	intel := got.CVEIntel[0]
	if !intel.KEV {
		t.Fatalf("expected KEV=true, got %#v", intel)
	}
	if intel.EPSS != 0.94412 || intel.EPSSPercentile != 0.99891 {
		t.Fatalf("unexpected EPSS values: %#v", intel)
	}
	if intel.VendorProject != "Oracle" || intel.Product != "WebLogic Server" {
		t.Fatalf("unexpected KEV product fields: %#v", intel)
	}
}

func TestLookupProductIncludesVulnrichment(t *testing.T) {
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
	vulnDir := filepath.Join(dir, "vulnrichment")
	if err := os.Mkdir(vulnDir, 0755); err != nil {
		t.Fatal(err)
	}
	vulnrichment := []byte(`{
  "cveMetadata": {"cveId": "CVE-2023-0001"},
  "containers": {
    "cna": {
      "affected": [
        {
          "vendor": "Example",
          "product": "Example Product",
          "cpes": ["cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*"]
        }
      ],
      "problemTypes": [
        {"descriptions": [{"cweId": "CWE-787", "description": "Out-of-bounds Write"}]}
      ],
      "metrics": [
        {
          "cvssV3_1": {
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        }
      ]
    },
    "adp": [
      {
        "metrics": [
          {
            "other": {
              "type": "ssvc",
              "content": {
                "options": [
                  {"Exploitation": "active"},
                  {"Automatable": "yes"}
                ]
              }
            }
          }
        ],
        "cpeApplicability": [
          {
            "nodes": [
              {
                "cpeMatch": [
                  {"criteria": "cpe:2.3:a:example:example_product:1.0:*:*:*:*:*:*:*"}
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}`)
	if err := os.WriteFile(filepath.Join(vulnDir, "CVE-2023-0001.json"), vulnrichment, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{
		NucleiTemplatesPath: dir,
		VulnrichmentPath:    vulnDir,
	})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("example-product")
	if len(got.CVEIntel) != 1 {
		t.Fatalf("expected cve intel, got %#v", got.CVEIntel)
	}
	intel := got.CVEIntel[0]
	if intel.CVSSScore != 9.8 || intel.CVSSSeverity != "CRITICAL" {
		t.Fatalf("unexpected CVSS: %#v", intel)
	}
	if !contains(intel.CWEs, "CWE-787") {
		t.Fatalf("missing CWE: %#v", intel.CWEs)
	}
	if !contains(intel.CPEs, "cpe:2.3:a:example:example_product:1.0:*:*:*:*:*:*:*") {
		t.Fatalf("missing CPE applicability: %#v", intel.CPEs)
	}
	if !contains(intel.SSVC, "Automatable:yes") || !contains(intel.SSVC, "Exploitation:active") {
		t.Fatalf("missing SSVC: %#v", intel.SSVC)
	}
}

func TestLookupProductUsesAliasFile(t *testing.T) {
	dir := t.TempDir()
	aliases := []byte(`
- name: ssh
  product: openssh
  tags:
    - openssh
  aliases:
    - open ssh
`)
	if err := os.WriteFile(filepath.Join(dir, "products.yaml"), aliases, 0644); err != nil {
		t.Fatal(err)
	}
	template := []byte(`
id: CVE-2001-1473
info:
  name: OpenSSH Detection
  severity: high
  tags:
    - openssh
  classification:
    cve-id:
      - CVE-2001-1473
`)
	if err := os.WriteFile(filepath.Join(dir, "openssh.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{
		NucleiTemplatesPath: dir,
		ProductAliasesPath:  filepath.Join(dir, "products.yaml"),
	})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("ssh")
	if len(got.TemplateIDs) != 1 || got.TemplateIDs[0] != "CVE-2001-1473" {
		t.Fatalf("unexpected template IDs: %#v", got.TemplateIDs)
	}
	if !contains(got.Tags, "openssh") {
		t.Fatalf("expected openssh tag, got %#v", got.Tags)
	}
}

func TestLookupProductUsesAliasAndVulnrichmentToFindCVETemplate(t *testing.T) {
	dir := t.TempDir()
	aliases := []byte(`
- name: oracle weblogic server
  vendor: Oracle
  product: WebLogic Server
  aliases:
    - weblogic
    - oracle weblogic
    - WebLogic Server
  tags:
    - weblogic
`)
	if err := os.WriteFile(filepath.Join(dir, "products.yaml"), aliases, 0644); err != nil {
		t.Fatal(err)
	}
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
      "affected": [
        {
          "vendor": "Oracle",
          "product": "WebLogic Server",
          "cpes": ["cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*"]
        }
      ],
      "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(dir, "CVE-2020-14882.json"), vuln, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{
		NucleiTemplatesPath: dir,
		ProductAliasesPath:  filepath.Join(dir, "products.yaml"),
		VulnrichmentPath:    filepath.Join(dir, "CVE-2020-14882.json"),
	})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("weblogic")
	if got.Product != "Oracle WebLogic Server" {
		t.Fatalf("unexpected canonical product: %q", got.Product)
	}
	if len(got.TemplateIDs) != 1 || got.TemplateIDs[0] != "CVE-2020-14882" {
		t.Fatalf("expected template from CVE reverse lookup, got %#v", got.TemplateIDs)
	}
	if !contains(got.CVEs, "CVE-2020-14882") {
		t.Fatalf("missing CVE: %#v", got.CVEs)
	}
	if !contains(got.CPEs, "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*") {
		t.Fatalf("missing CPE: %#v", got.CPEs)
	}
}

func TestLookupProductUsesProductTokenWithoutAliasFile(t *testing.T) {
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
      "affected": [{"vendor": "Oracle", "product": "WebLogic Server"}]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(dir, "CVE-2020-14882.json"), vuln, 0644); err != nil {
		t.Fatal(err)
	}
	idx, err := Load(Options{
		NucleiTemplatesPath: dir,
		VulnrichmentPath:    filepath.Join(dir, "CVE-2020-14882.json"),
	})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("weblogic")
	if !contains(got.CVEs, "CVE-2020-14882") {
		t.Fatalf("expected product token lookup to find CVE, got %#v", got.CVEs)
	}
	if !contains(got.TemplateIDs, "CVE-2020-14882") {
		t.Fatalf("expected CVE reverse lookup to find template, got %#v", got.TemplateIDs)
	}
}

func TestInfoTemplateDoesNotBecomePreciseID(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: weblogic-detect
info:
  name: WebLogic Detect
  severity: info
  tags: detect,weblogic
`)
	if err := os.WriteFile(filepath.Join(dir, "detect.yaml"), template, 0644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(Options{NucleiTemplatesPath: dir})
	if err != nil {
		t.Fatalf("load index: %v", err)
	}
	got := idx.LookupProduct("weblogic")
	if len(got.TemplateIDs) != 0 {
		t.Fatalf("info detect template should not be precise IDs: %#v", got.TemplateIDs)
	}
	if !contains(got.Tags, "weblogic") {
		t.Fatalf("expected weblogic tag fallback, got %#v", got.Tags)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
