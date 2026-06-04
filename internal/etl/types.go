package etl

// Entity is a normalized asset extracted from a raw artifact result.
type Entity struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // ip, port, service, fingerprint, vulnerability, url, template, cve
	Value       string    `json:"value"`
	Source      string    `json:"source"` // which artifact produced it
	TargetID    string    `json:"target_id"`
	RawData     []byte    `json:"raw_data,omitempty"`
	Product     string    `json:"product,omitempty"`
	Version     string    `json:"version,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Priority    int       `json:"priority,omitempty"`
	Status      string    `json:"status,omitempty"` // observed, candidate, confirmed
	Reason      string    `json:"reason,omitempty"` // human-readable explanation for enrichment/planning
	SourceRunID string    `json:"source_run_id,omitempty"`
	Quality     *Quality  `json:"quality,omitempty"`      // normalized data quality metadata
	TemplateIDs []string  `json:"template_ids,omitempty"` // enriched template candidates
	Tags        []string  `json:"tags,omitempty"`         // enrichment tags
	CVEs        []string  `json:"cves,omitempty"`         // enriched vulnerability candidates
	CPEs        []string  `json:"cpes,omitempty"`         // enriched platform candidates
	CVEIntel    []CVEInfo `json:"cve_intel,omitempty"`    // enriched KEV/EPSS details
}

type Quality struct {
	CanonicalValue string   `json:"canonical_value,omitempty"`
	Layer          string   `json:"layer,omitempty"` // critical, interesting, normal, noise
	Noise          bool     `json:"noise,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	HTTP           HTTPMeta `json:"http,omitempty"`
}

type HTTPMeta struct {
	URL           string `json:"url,omitempty"`
	Scheme        string `json:"scheme,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          string `json:"port,omitempty"`
	Path          string `json:"path,omitempty"`
	Query         string `json:"query,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	Title         string `json:"title,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length,omitempty"`
	BodyHash      string `json:"body_hash,omitempty"`
	BodySimhash   string `json:"body_simhash,omitempty"`
	FaviconHash   string `json:"favicon_hash,omitempty"`
	Location      string `json:"location,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

type CVEInfo struct {
	ID                         string   `json:"id"`
	KEV                        bool     `json:"kev,omitempty"`
	EPSS                       float64  `json:"epss,omitempty"`
	EPSSPercentile             float64  `json:"epss_percentile,omitempty"`
	CVSSScore                  float64  `json:"cvss_score,omitempty"`
	CVSSSeverity               string   `json:"cvss_severity,omitempty"`
	CVSSVector                 string   `json:"cvss_vector,omitempty"`
	VendorProject              string   `json:"vendor_project,omitempty"`
	Product                    string   `json:"product,omitempty"`
	CPEs                       []string `json:"cpes,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
	SSVC                       []string `json:"ssvc,omitempty"`
	VulnerabilityName          string   `json:"vulnerability_name,omitempty"`
	DateAdded                  string   `json:"date_added,omitempty"`
	DueDate                    string   `json:"due_date,omitempty"`
	KnownRansomwareCampaignUse string   `json:"known_ransomware_campaign_use,omitempty"`
	RequiredAction             string   `json:"required_action,omitempty"`
	ShortDescription           string   `json:"short_description,omitempty"`
	Notes                      string   `json:"notes,omitempty"`
}

// Relation links two entities in the asset graph with explicit direction.
type Relation struct {
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Type   string `json:"type"` // has_port, runs, has_fingerprint, has_vuln
}

// ExtractResult separates entities and relations to avoid direction ambiguity.
type ExtractResult struct {
	Entities  []Entity
	Relations []Relation
}
