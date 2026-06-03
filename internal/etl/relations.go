package etl

// Relation type constants — the canonical relationship vocabulary for the ASM graph.
// Every ETL extractor MUST use only these types.
const (
	RelOwns              = "owns"               // target → domain, company → domain
	RelResolvesTo        = "resolves_to"        // domain → ip
	RelHasPort           = "has_port"           // ip → port
	RelRuns              = "runs"               // port → service
	RelExposes           = "exposes"            // service → url
	RelHasFingerprint    = "has_fingerprint"    // service → fingerprint
	RelIdentifiesProduct = "identifies_product" // fingerprint → product
	RelHasVersion        = "has_version"        // product → version
	RelAffectedBy        = "affected_by"        // product → cve
	RelHasTemplate       = "has_template"       // cve → template
	RelHasIntel          = "has_intel"          // cve → intel
	RelHasCPE            = "has_cpe"            // cve → cpe
	RelHasCWE            = "has_cwe"            // cve → cwe
	RelRelatesTo         = "relates_to"         // fingerprint → template
	RelDetects           = "detects"            // template → vulnerability
	RelHasVulnerability  = "has_vulnerability"  // url → vulnerability
	RelHasCredential     = "has_credential"     // service → credential
	RelProtectedBy       = "protected_by"       // domain/ip → protection
	RelDiscoveredBy      = "discovered_by"      // asset → raw_event
)

// ValidRelation returns true if the given relation type is in the whitelist.
func ValidRelation(relType string) bool {
	switch relType {
	case RelOwns, RelResolvesTo, RelHasPort, RelRuns, RelExposes,
		RelHasFingerprint, RelIdentifiesProduct, RelHasVersion, RelAffectedBy,
		RelHasTemplate, RelHasIntel, RelHasCPE, RelHasCWE, RelRelatesTo, RelDetects,
		RelHasVulnerability, RelHasCredential, RelProtectedBy, RelDiscoveredBy:
		return true
	}
	return false
}
