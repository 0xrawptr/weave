package etl

import (
	"context"
	"log"

	"github.com/0xrawptr/weave/internal/knowledge"
	sdkclient "github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/association"
)

// Enricher augments extracted entities with derived knowledge.
type Enricher interface {
	Enrich(ctx context.Context, result *ExtractResult) (*ExtractResult, error)
}

// MultiEnricher runs multiple enrichment sources in order.
type MultiEnricher struct {
	enrichers []Enricher
}

func NewMultiEnricher(enrichers ...Enricher) *MultiEnricher {
	var filtered []Enricher
	for _, e := range enrichers {
		if e != nil {
			filtered = append(filtered, e)
		}
	}
	return &MultiEnricher{enrichers: filtered}
}

func (m *MultiEnricher) Enrich(ctx context.Context, result *ExtractResult) (*ExtractResult, error) {
	var err error
	for _, enricher := range m.enrichers {
		result, err = enricher.Enrich(ctx, result)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// AssociationEnricher uses the SDK's association index to look up templates
// and CVEs related to discovered fingerprints.
type AssociationEnricher struct {
	client *sdkclient.Client
}

// NewAssociationEnricher creates an enricher backed by the SDK client's index.
func NewAssociationEnricher(c *sdkclient.Client) *AssociationEnricher {
	return &AssociationEnricher{client: c}
}

// Enrich queries the SDK association index for each fingerprint entity and
// appends related template IDs on the entity.
func (a *AssociationEnricher) Enrich(ctx context.Context, result *ExtractResult) (*ExtractResult, error) {
	if result == nil || a.client == nil {
		return result, nil
	}

	idx, err := a.client.Index()
	if err != nil || idx == nil {
		log.Printf("WARNING: enrichment skipped — index not available: %v", err)
		return result, nil
	}

	for i, e := range result.Entities {
		if e.Type != "fingerprint" {
			continue
		}
		q := association.NewQuery().WithFingers(e.Value)
		qr := idx.Lookup(q)
		if qr == nil {
			continue
		}
		for _, tpl := range qr.Templates {
			if tpl != nil && tpl.Id != "" {
				result.Entities[i].TemplateIDs = appendUniqueString(result.Entities[i].TemplateIDs, tpl.Id)
			}
		}
	}
	return result, nil
}

// KnowledgeEnricher uses the local nuclei-template knowledge index.
type KnowledgeEnricher struct {
	index *knowledge.Index
}

func NewKnowledgeEnricher(index *knowledge.Index) *KnowledgeEnricher {
	return &KnowledgeEnricher{index: index}
}

func (k *KnowledgeEnricher) Enrich(ctx context.Context, result *ExtractResult) (*ExtractResult, error) {
	if result == nil || k == nil || k.index == nil || k.index.Len() == 0 {
		return result, nil
	}

	for i, e := range result.Entities {
		if e.Type != "fingerprint" {
			continue
		}
		enriched := knowledge.Enrichment{}
		for _, term := range appendUniqueString(nil, e.Value, e.Product) {
			enriched = mergeKnowledgeEnrichment(enriched, k.index.LookupProduct(term))
		}
		if enriched.Product != "" {
			result.Entities[i].Product = enriched.Product
		}
		result.Entities[i].TemplateIDs = appendUniqueString(result.Entities[i].TemplateIDs, enriched.TemplateIDs...)
		result.Entities[i].Tags = appendUniqueString(result.Entities[i].Tags, enriched.Tags...)
		result.Entities[i].CVEs = appendUniqueString(result.Entities[i].CVEs, enriched.CVEs...)
		result.Entities[i].CPEs = appendUniqueString(result.Entities[i].CPEs, enriched.CPEs...)
		result.Entities[i].CVEIntel = mergeCVEInfo(result.Entities[i].CVEIntel, convertCVEIntel(enriched.CVEIntel)...)
		if len(enriched.TemplateIDs) > 0 || len(enriched.CVEs) > 0 {
			result.Entities[i].Reason = "fingerprint matched local knowledge candidates"
		}
	}
	return result, nil
}

func mergeKnowledgeEnrichment(base, addition knowledge.Enrichment) knowledge.Enrichment {
	if addition.Product != "" {
		base.Product = addition.Product
	}
	if addition.Vendor != "" {
		base.Vendor = addition.Vendor
	}
	base.CPEs = appendUniqueString(base.CPEs, addition.CPEs...)
	base.TemplateIDs = appendUniqueString(base.TemplateIDs, addition.TemplateIDs...)
	base.Tags = appendUniqueString(base.Tags, addition.Tags...)
	base.CVEs = appendUniqueString(base.CVEs, addition.CVEs...)
	base.CVEIntel = mergeKnowledgeCVEIntel(base.CVEIntel, addition.CVEIntel...)
	base.Templates = append(base.Templates, addition.Templates...)
	return base
}

func mergeKnowledgeCVEIntel(values []knowledge.CVEIntel, additions ...knowledge.CVEIntel) []knowledge.CVEIntel {
	seen := make(map[string]int, len(values)+len(additions))
	for i, value := range values {
		if value.ID != "" {
			seen[value.ID] = i
		}
	}
	for _, addition := range additions {
		if addition.ID == "" {
			continue
		}
		if _, ok := seen[addition.ID]; ok {
			continue
		}
		seen[addition.ID] = len(values)
		values = append(values, addition)
	}
	return values
}

func convertCVEIntel(values []knowledge.CVEIntel) []CVEInfo {
	out := make([]CVEInfo, 0, len(values))
	for _, value := range values {
		if value.ID == "" {
			continue
		}
		out = append(out, CVEInfo{
			ID:                         value.ID,
			KEV:                        value.KEV,
			EPSS:                       value.EPSS,
			EPSSPercentile:             value.EPSSPercentile,
			CVSSScore:                  value.CVSSScore,
			CVSSSeverity:               value.CVSSSeverity,
			CVSSVector:                 value.CVSSVector,
			VendorProject:              value.VendorProject,
			Product:                    value.Product,
			CPEs:                       value.CPEs,
			CWEs:                       value.CWEs,
			SSVC:                       value.SSVC,
			VulnerabilityName:          value.VulnerabilityName,
			DateAdded:                  value.DateAdded,
			DueDate:                    value.DueDate,
			KnownRansomwareCampaignUse: value.KnownRansomwareCampaignUse,
			RequiredAction:             value.RequiredAction,
			ShortDescription:           value.ShortDescription,
			Notes:                      value.Notes,
		})
	}
	return out
}

func mergeCVEInfo(values []CVEInfo, additions ...CVEInfo) []CVEInfo {
	seen := make(map[string]int, len(values)+len(additions))
	for i, value := range values {
		if value.ID == "" {
			continue
		}
		seen[value.ID] = i
	}
	for _, addition := range additions {
		if addition.ID == "" {
			continue
		}
		if i, ok := seen[addition.ID]; ok {
			values[i] = mergeOneCVEInfo(values[i], addition)
			continue
		}
		seen[addition.ID] = len(values)
		values = append(values, addition)
	}
	return values
}

func mergeOneCVEInfo(base, addition CVEInfo) CVEInfo {
	if addition.KEV {
		base.KEV = true
	}
	if addition.EPSS != 0 {
		base.EPSS = addition.EPSS
	}
	if addition.EPSSPercentile != 0 {
		base.EPSSPercentile = addition.EPSSPercentile
	}
	if addition.CVSSScore != 0 && addition.CVSSScore >= base.CVSSScore {
		base.CVSSScore = addition.CVSSScore
		base.CVSSSeverity = addition.CVSSSeverity
		base.CVSSVector = addition.CVSSVector
	}
	if addition.VendorProject != "" {
		base.VendorProject = addition.VendorProject
	}
	if addition.Product != "" {
		base.Product = addition.Product
	}
	base.CPEs = appendUniqueString(base.CPEs, addition.CPEs...)
	base.CWEs = appendUniqueString(base.CWEs, addition.CWEs...)
	base.SSVC = appendUniqueString(base.SSVC, addition.SSVC...)
	if addition.VulnerabilityName != "" {
		base.VulnerabilityName = addition.VulnerabilityName
	}
	if addition.DateAdded != "" {
		base.DateAdded = addition.DateAdded
	}
	if addition.DueDate != "" {
		base.DueDate = addition.DueDate
	}
	if addition.KnownRansomwareCampaignUse != "" {
		base.KnownRansomwareCampaignUse = addition.KnownRansomwareCampaignUse
	}
	if addition.RequiredAction != "" {
		base.RequiredAction = addition.RequiredAction
	}
	if addition.ShortDescription != "" {
		base.ShortDescription = addition.ShortDescription
	}
	if addition.Notes != "" {
		base.Notes = addition.Notes
	}
	return base
}

func appendUniqueString(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		if value == "" {
			continue
		}
		seen[value] = true
	}
	for _, value := range additions {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	return values
}
