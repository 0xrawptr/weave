package etl

// Entity is a normalized asset extracted from a raw artifact result.
type Entity struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // ip, port, service, fingerprint, vulnerability, url
	Value    string   `json:"value"`
	Source   string   `json:"source"` // which artifact produced it
	TargetID string   `json:"target_id"`
	RawData  []byte   `json:"raw_data,omitempty"`
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
