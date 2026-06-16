package etl

import (
	"context"
	"log"
	"net/url"
	"strings"

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
// and CVEs related to discovered assets.
type AssociationEnricher struct {
	client *sdkclient.Client
}

// NewAssociationEnricher creates an enricher backed by the SDK client's index.
func NewAssociationEnricher(c *sdkclient.Client) *AssociationEnricher {
	return &AssociationEnricher{client: c}
}

// Enrich queries the SDK association index for each entity that has useful
// association hints. The SDK index can correlate fingerprints, services,
// aliases, CPEs, tags, CVEs, and POC templates; feed it every normalized hint
// we have instead of only the display fingerprint name.
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
		q := associationQueryForEntity(e)
		if q == nil {
			continue
		}
		qr := idx.Lookup(q)
		if qr == nil {
			continue
		}
		result.Entities[i] = applyAssociationResult(result.Entities[i], qr)
	}
	return result, nil
}

func associationQueryForEntity(e Entity) *association.Query {
	q := association.NewQuery().
		WithTags(e.Tags...).
		WithCPEs(e.CPEs...).
		WithCVEs(e.CVEs...).
		WithTemplates(e.TemplateIDs...)

	switch e.Type {
	case "fingerprint":
		q.WithFingers(e.Value).
			WithAliases(e.Value, e.Product).
			WithAttr("product", e.Product)
	case "service":
		q.WithServices(serviceAssociationTerms(e.Value, e.Product)...)
	case "template":
		q.WithTemplates(e.Value)
	case "cve":
		q.WithCVEs(e.Value)
	case "cpe":
		q.WithCPEs(e.Value)
	case "vulnerability":
		q.WithTemplates(e.TemplateIDs...).
			WithCVEs(e.CVEs...).
			WithAttr("severity", e.Severity)
	default:
		return nil
	}
	if len(q.Fingers) == 0 &&
		len(q.Aliases) == 0 &&
		len(q.Templates) == 0 &&
		len(q.Tags) == 0 &&
		len(q.Services) == 0 &&
		len(q.CPEs) == 0 &&
		len(q.CVEs) == 0 &&
		len(q.Attributes) == 0 {
		return nil
	}
	return q
}

func serviceAssociationTerms(values ...string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			out = appendUniqueString(out, parsed.Scheme)
			continue
		}
		if strings.Contains(value, "://") {
			continue
		}
		if host, port, ok := strings.Cut(value, ":"); ok && host != "" && port != "" {
			out = appendUniqueString(out, serviceNameForPort(port))
			continue
		}
		out = appendUniqueString(out, value)
	}
	return out
}

func serviceNameForPort(port string) string {
	switch strings.TrimSpace(port) {
	case "21":
		return "ftp"
	case "22":
		return "ssh"
	case "80", "8080":
		return "http"
	case "443", "8443":
		return "https"
	case "445":
		return "smb"
	case "3306":
		return "mysql"
	case "5432":
		return "postgresql"
	case "6379":
		return "redis"
	case "27017":
		return "mongo"
	default:
		return ""
	}
}

func applyAssociationResult(entity Entity, qr *association.QueryResult) Entity {
	beforeTemplates := len(entity.TemplateIDs)
	beforeCVEs := len(entity.CVEs)
	beforeCPEs := len(entity.CPEs)
	for _, tpl := range qr.Templates {
		if tpl == nil || tpl.Id == "" {
			continue
		}
		entity.TemplateIDs = appendUniqueString(entity.TemplateIDs, tpl.Id)
		entity.Tags = appendUniqueString(entity.Tags, tpl.GetTags()...)
		if entity.Severity == "" {
			entity.Severity = strings.ToLower(strings.TrimSpace(tpl.Info.Severity))
		}
		if tpl.Info.Classification != nil {
			entity.CVEs = appendUniqueString(entity.CVEs, tpl.Info.Classification.CVEID)
			entity.CPEs = appendUniqueString(entity.CPEs, tpl.Info.Classification.CPE)
		}
	}
	for _, finger := range qr.Fingers {
		if finger == nil {
			continue
		}
		entity.Tags = appendUniqueString(entity.Tags, finger.Tags...)
	}
	for _, alias := range qr.Aliases {
		if alias == nil {
			continue
		}
		entity.Tags = appendUniqueString(entity.Tags, alias.Tags...)
		if entity.Product == "" && alias.Product != "" {
			entity.Product = alias.Product
		}
	}
	if len(entity.TemplateIDs) > beforeTemplates || len(entity.CVEs) > beforeCVEs || len(entity.CPEs) > beforeCPEs {
		entity.Reason = "entity matched SDK association candidates"
	}
	return entity
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
