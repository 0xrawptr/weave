package knowledge

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultMaxTemplatesPerProduct = 80

type Options struct {
	NucleiTemplatesPath   string
	ProductAliasesPath    string
	KEVPath               string
	EPSSPath              string
	VulnrichmentPath      string
	MaxTemplatesPerLookup int
}

type ProductAlias struct {
	Name    string   `yaml:"name"`
	Aliases []string `yaml:"aliases"`
	Vendor  string   `yaml:"vendor"`
	Product string   `yaml:"product"`
	Tags    []string `yaml:"tags"`
	CPEs    []string `yaml:"cpes"`
}

type CanonicalProduct struct {
	Name    string
	Vendor  string
	Product string
	Tags    []string
	CPEs    []string
}

type TemplateRef struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
	CVEs     []string
	CPEs     []string
	Vendor   string
	Product  string
}

type Enrichment struct {
	Product     string
	Vendor      string
	CPEs        []string
	TemplateIDs []string
	Tags        []string
	CVEs        []string
	CVEIntel    []CVEIntel
	Templates   []TemplateRef
}

type Index struct {
	templates []TemplateRef
	byKey     map[string][]int
	byCVE     map[string][]int
	aliases   map[string][]string
	aliasTags map[string][]string
	canonical map[string]CanonicalProduct
	cves      map[string]CVEIntel
	cveByKey  map[string][]string
	cpeByKey  map[string][]string
	max       int
}

type CVEIntel struct {
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

func Load(options Options) (*Index, error) {
	idx := &Index{
		byKey:     make(map[string][]int),
		byCVE:     make(map[string][]int),
		aliases:   make(map[string][]string),
		aliasTags: make(map[string][]string),
		canonical: make(map[string]CanonicalProduct),
		cves:      make(map[string]CVEIntel),
		cveByKey:  make(map[string][]string),
		cpeByKey:  make(map[string][]string),
		max:       options.MaxTemplatesPerLookup,
	}
	if idx.max <= 0 {
		idx.max = defaultMaxTemplatesPerProduct
	}

	if options.ProductAliasesPath != "" {
		if err := idx.loadAliases(options.ProductAliasesPath); err != nil {
			return nil, err
		}
	}
	if options.VulnrichmentPath != "" {
		if err := idx.loadVulnrichment(options.VulnrichmentPath); err != nil {
			return nil, err
		}
	}
	if options.KEVPath != "" {
		if err := idx.loadKEV(options.KEVPath); err != nil {
			return nil, err
		}
	}
	if options.EPSSPath != "" {
		if err := idx.loadEPSS(options.EPSSPath); err != nil {
			return nil, err
		}
	}
	if options.NucleiTemplatesPath == "" {
		return idx, nil
	}
	if err := idx.loadTemplates(options.NucleiTemplatesPath); err != nil {
		return nil, err
	}
	return idx, nil
}

func (idx *Index) Len() int {
	if idx == nil {
		return 0
	}
	return len(idx.templates)
}

func (idx *Index) CVELen() int {
	if idx == nil {
		return 0
	}
	return len(idx.cves)
}

func (idx *Index) LookupProduct(name string) Enrichment {
	if idx == nil || strings.TrimSpace(name) == "" {
		return Enrichment{}
	}

	keys := idx.lookupKeys(name)
	if len(keys) == 0 {
		return Enrichment{}
	}
	canonical := idx.lookupCanonical(name, keys)

	type scored struct {
		ref   TemplateRef
		score int
	}
	seenTemplates := make(map[string]bool)
	var candidates []scored
	matchedTags := make(map[string]bool)
	seenCVEs := make(map[string]bool)
	seenCPEs := make(map[string]bool)

	addCVE := func(cve string) {
		cve = normalizeCVE(cve)
		if cve != "" {
			seenCVEs[cve] = true
		}
	}
	addCPE := func(cpe string) {
		cpe = strings.TrimSpace(cpe)
		if cpe != "" {
			seenCPEs[cpe] = true
		}
	}
	addTemplate := func(tpl TemplateRef) {
		if tpl.ID == "" || seenTemplates[tpl.ID] {
			return
		}
		seenTemplates[tpl.ID] = true
		candidates = append(candidates, scored{ref: tpl, score: scoreTemplate(tpl)})
		for _, cve := range tpl.CVEs {
			addCVE(cve)
		}
		for _, cpe := range tpl.CPEs {
			addCPE(cpe)
		}
	}
	addTemplatesByCVE := func(cve string) {
		cve = normalizeCVE(cve)
		if cve == "" {
			return
		}
		for _, id := range idx.byCVE[cve] {
			if id >= 0 && id < len(idx.templates) {
				addTemplate(idx.templates[id])
			}
		}
	}

	for _, key := range keys {
		for _, id := range idx.byKey[key] {
			if id < 0 || id >= len(idx.templates) {
				continue
			}
			tpl := idx.templates[id]
			addTemplate(tpl)
			for _, tag := range tpl.Tags {
				if normalizeKey(tag) == key {
					matchedTags[tag] = true
				}
			}
		}
		for _, cve := range idx.cveByKey[key] {
			addCVE(cve)
		}
		for _, cpe := range idx.cpeByKey[key] {
			addCPE(cpe)
		}
	}

	for _, cpe := range canonical.CPEs {
		addCPE(cpe)
		for _, key := range cpeLookupKeys(cpe) {
			for _, cve := range idx.cveByKey[key] {
				addCVE(cve)
			}
		}
	}
	for cve := range seenCVEs {
		addTemplatesByCVE(cve)
	}
	for cpe := range seenCPEs {
		for _, key := range cpeLookupKeys(cpe) {
			for _, cve := range idx.cveByKey[key] {
				addCVE(cve)
				addTemplatesByCVE(cve)
			}
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].ref.ID < candidates[j].ref.ID
		}
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > idx.max {
		candidates = candidates[:idx.max]
	}

	out := Enrichment{
		Product: canonical.Name,
		Vendor:  canonical.Vendor,
		CPEs:    uniqueSortedStrings(mapKeys(seenCPEs)),
	}
	seenIDs := make(map[string]bool)
	for _, item := range candidates {
		tpl := item.ref
		out.Templates = append(out.Templates, tpl)
		if shouldUseTemplateID(tpl) && !seenIDs[tpl.ID] {
			seenIDs[tpl.ID] = true
			out.TemplateIDs = append(out.TemplateIDs, tpl.ID)
		}
		for _, cve := range tpl.CVEs {
			addCVE(cve)
		}
	}

	out.CVEs = uniqueSortedStrings(mapKeys(seenCVEs))
	for _, cve := range out.CVEs {
		intel := idx.LookupCVE(cve)
		out.CVEIntel = append(out.CVEIntel, intel)
		out.CPEs = appendUnique(out.CPEs, intel.CPEs...)
	}
	out.CPEs = uniqueSortedStrings(out.CPEs)

	for _, key := range keys {
		for _, tag := range idx.aliasTags[key] {
			matchedTags[tag] = true
		}
	}
	for _, tag := range canonical.Tags {
		matchedTags[tag] = true
	}
	for tag := range matchedTags {
		out.Tags = append(out.Tags, tag)
	}
	sort.Strings(out.Tags)
	return out
}

func (idx *Index) LookupCVE(id string) CVEIntel {
	id = normalizeCVE(id)
	if id == "" {
		return CVEIntel{}
	}
	if idx == nil {
		return CVEIntel{ID: id}
	}
	if intel, ok := idx.cves[id]; ok {
		intel.ID = id
		return intel
	}
	return CVEIntel{ID: id}
}

func (idx *Index) loadAliases(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read product aliases: %w", err)
	}
	var aliases []ProductAlias
	if err := yaml.Unmarshal(data, &aliases); err != nil {
		return fmt.Errorf("parse product aliases: %w", err)
	}
	for _, item := range aliases {
		keys := candidateKeys(item.Name)
		keys = append(keys, productKeys(item.Product)...)
		keys = append(keys, candidateKeys(item.Vendor+" "+item.Product)...)
		for _, alias := range item.Aliases {
			keys = append(keys, candidateKeys(alias)...)
		}
		for _, tag := range item.Tags {
			keys = append(keys, candidateKeys(tag)...)
		}
		for _, cpe := range item.CPEs {
			vendor, product := cpeVendorProduct(cpe)
			keys = append(keys, candidateKeys(vendor+" "+product)...)
			keys = append(keys, candidateKeys(product)...)
		}

		values := uniqueStrings(keys)
		canonical := canonicalFromAlias(item)
		for _, key := range values {
			idx.aliases[key] = appendUnique(idx.aliases[key], values...)
			idx.aliasTags[key] = appendUnique(idx.aliasTags[key], item.Tags...)
			idx.canonical[key] = mergeCanonicalProduct(idx.canonical[key], canonical)
			idx.cpeByKey[key] = appendUnique(idx.cpeByKey[key], item.CPEs...)
		}
	}
	return nil
}

func (idx *Index) loadTemplates(root string) error {
	stat, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat nuclei templates path: %w", err)
	}
	if !stat.IsDir() {
		return idx.loadTemplateFile(root)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		return idx.loadTemplateFile(path)
	})
}

func (idx *Index) loadKEV(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read KEV: %w", err)
	}
	var feed struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			ShortDescription           string `json:"shortDescription"`
			RequiredAction             string `json:"requiredAction"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			Notes                      string `json:"notes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &feed); err != nil {
		return fmt.Errorf("parse KEV: %w", err)
	}
	for _, vuln := range feed.Vulnerabilities {
		id := normalizeCVE(vuln.CVEID)
		if id == "" {
			continue
		}
		intel := idx.cves[id]
		intel.ID = id
		intel.KEV = true
		intel.VendorProject = vuln.VendorProject
		intel.Product = vuln.Product
		intel.VulnerabilityName = vuln.VulnerabilityName
		intel.DateAdded = vuln.DateAdded
		intel.ShortDescription = vuln.ShortDescription
		intel.RequiredAction = vuln.RequiredAction
		intel.DueDate = vuln.DueDate
		intel.KnownRansomwareCampaignUse = vuln.KnownRansomwareCampaignUse
		intel.Notes = vuln.Notes
		idx.cves[id] = intel
		idx.indexCVEIntel(intel)
	}
	return nil
}

func (idx *Index) loadEPSS(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read EPSS: %w", err)
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("open EPSS gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	csvReader := csv.NewReader(reader)
	csvReader.Comment = '#'
	csvReader.FieldsPerRecord = -1

	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("read EPSS header: %w", err)
	}
	cols := csvColumns(header)
	cveCol, epssCol, percentileCol := cols["cve"], cols["epss"], cols["percentile"]
	if cveCol < 0 || epssCol < 0 || percentileCol < 0 {
		return fmt.Errorf("invalid EPSS header: %v", header)
	}

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read EPSS record: %w", err)
		}
		if len(record) <= percentileCol {
			continue
		}
		id := normalizeCVE(record[cveCol])
		if id == "" {
			continue
		}
		epss, _ := strconv.ParseFloat(strings.TrimSpace(record[epssCol]), 64)
		percentile, _ := strconv.ParseFloat(strings.TrimSpace(record[percentileCol]), 64)
		intel := idx.cves[id]
		intel.ID = id
		intel.EPSS = epss
		intel.EPSSPercentile = percentile
		idx.cves[id] = intel
	}
	return nil
}

func (idx *Index) loadVulnrichment(root string) error {
	stat, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat Vulnrichment path: %w", err)
	}
	if !stat.IsDir() {
		return idx.loadVulnrichmentFile(root)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".json" {
			return nil
		}
		return idx.loadVulnrichmentFile(path)
	})
}

func (idx *Index) loadVulnrichmentFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record vulnrichmentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil
	}
	intel := record.toCVEIntel()
	if intel.ID == "" {
		return nil
	}
	existing := idx.cves[intel.ID]
	merged := mergeCVEIntel(existing, intel)
	idx.cves[intel.ID] = merged
	idx.indexCVEIntel(merged)
	return nil
}

type vulnrichmentRecord struct {
	CVEMetadata struct {
		CVEID string `json:"cveId"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA vulnrichmentContainer   `json:"cna"`
		ADP []vulnrichmentContainer `json:"adp"`
	} `json:"containers"`
}

type vulnrichmentContainer struct {
	Affected         []vulnrichmentAffected         `json:"affected"`
	ProblemTypes     []vulnrichmentProblemType      `json:"problemTypes"`
	Metrics          []vulnrichmentMetric           `json:"metrics"`
	CPEApplicability []vulnrichmentCPEApplicability `json:"cpeApplicability"`
}

type vulnrichmentAffected struct {
	Vendor  string   `json:"vendor"`
	Product string   `json:"product"`
	CPEs    []string `json:"cpes"`
}

type vulnrichmentProblemType struct {
	Descriptions []struct {
		CWEID       string `json:"cweId"`
		Description string `json:"description"`
	} `json:"descriptions"`
}

type vulnrichmentMetric struct {
	CVSSV40 *vulnrichmentCVSS  `json:"cvssV4_0"`
	CVSSV31 *vulnrichmentCVSS  `json:"cvssV3_1"`
	CVSSV30 *vulnrichmentCVSS  `json:"cvssV3_0"`
	Other   *vulnrichmentOther `json:"other"`
}

type vulnrichmentCVSS struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type vulnrichmentOther struct {
	Type    string          `json:"type"`
	Content json.RawMessage `json:"content"`
}

type vulnrichmentCPEApplicability struct {
	Nodes []vulnrichmentCPENode `json:"nodes"`
}

type vulnrichmentCPENode struct {
	CPEMatch []struct {
		Criteria string `json:"criteria"`
	} `json:"cpeMatch"`
}

func (r vulnrichmentRecord) toCVEIntel() CVEIntel {
	id := normalizeCVE(r.CVEMetadata.CVEID)
	if id == "" {
		return CVEIntel{}
	}
	out := CVEIntel{ID: id}
	out = mergeCVEIntel(out, r.Containers.CNA.toCVEIntel(id))
	for _, container := range r.Containers.ADP {
		out = mergeCVEIntel(out, container.toCVEIntel(id))
	}
	return out
}

func (c vulnrichmentContainer) toCVEIntel(id string) CVEIntel {
	out := CVEIntel{ID: id}
	for _, affected := range c.Affected {
		if out.VendorProject == "" && affected.Vendor != "" {
			out.VendorProject = affected.Vendor
		}
		if out.Product == "" && affected.Product != "" {
			out.Product = affected.Product
		}
		out.CPEs = appendUnique(out.CPEs, affected.CPEs...)
	}
	for _, problemType := range c.ProblemTypes {
		for _, desc := range problemType.Descriptions {
			if cwe := normalizeCWE(desc.CWEID); cwe != "" {
				out.CWEs = appendUnique(out.CWEs, cwe)
			}
			if cwe := normalizeCWE(desc.Description); cwe != "" {
				out.CWEs = appendUnique(out.CWEs, cwe)
			}
		}
	}
	for _, metric := range c.Metrics {
		out = mergeBestCVSS(out, metric.cvss())
		if metric.Other != nil && strings.EqualFold(metric.Other.Type, "ssvc") {
			out.SSVC = appendUnique(out.SSVC, parseSSVC(metric.Other.Content)...)
		}
	}
	for _, applicability := range c.CPEApplicability {
		for _, node := range applicability.Nodes {
			for _, match := range node.CPEMatch {
				if match.Criteria != "" {
					out.CPEs = appendUnique(out.CPEs, match.Criteria)
				}
			}
		}
	}
	return out
}

func (m vulnrichmentMetric) cvss() *vulnrichmentCVSS {
	if m.CVSSV40 != nil {
		return m.CVSSV40
	}
	if m.CVSSV31 != nil {
		return m.CVSSV31
	}
	return m.CVSSV30
}

func mergeCVEIntel(base, addition CVEIntel) CVEIntel {
	if base.ID == "" {
		base.ID = addition.ID
	}
	if addition.KEV {
		base.KEV = true
	}
	if addition.EPSS != 0 {
		base.EPSS = addition.EPSS
	}
	if addition.EPSSPercentile != 0 {
		base.EPSSPercentile = addition.EPSSPercentile
	}
	base = mergeBestCVSS(base, &vulnrichmentCVSS{
		BaseScore:    addition.CVSSScore,
		BaseSeverity: addition.CVSSSeverity,
		VectorString: addition.CVSSVector,
	})
	if addition.VendorProject != "" {
		base.VendorProject = addition.VendorProject
	}
	if addition.Product != "" {
		base.Product = addition.Product
	}
	base.CPEs = appendUnique(base.CPEs, addition.CPEs...)
	base.CWEs = appendUnique(base.CWEs, addition.CWEs...)
	base.SSVC = appendUnique(base.SSVC, addition.SSVC...)
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

func mergeBestCVSS(base CVEIntel, cvss *vulnrichmentCVSS) CVEIntel {
	if cvss == nil || cvss.BaseScore == 0 {
		return base
	}
	if cvss.BaseScore >= base.CVSSScore {
		base.CVSSScore = cvss.BaseScore
		base.CVSSSeverity = cvss.BaseSeverity
		base.CVSSVector = cvss.VectorString
	}
	return base
}

func parseSSVC(data json.RawMessage) []string {
	var content struct {
		Options []map[string]string `json:"options"`
	}
	if err := json.Unmarshal(data, &content); err != nil {
		return nil
	}
	var out []string
	for _, option := range content.Options {
		for key, value := range option {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			out = append(out, key+":"+value)
		}
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func (idx *Index) loadTemplateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var tpl rawTemplate
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return nil
	}
	ref := tpl.toRef()
	if ref.ID == "" {
		return nil
	}
	id := len(idx.templates)
	idx.templates = append(idx.templates, ref)
	for _, key := range ref.indexKeys() {
		idx.byKey[key] = appendUniqueInt(idx.byKey[key], id)
	}
	for _, cve := range ref.CVEs {
		idx.byCVE[cve] = appendUniqueInt(idx.byCVE[cve], id)
	}
	return nil
}

func (idx *Index) lookupKeys(name string) []string {
	keys := candidateKeys(name)
	for _, key := range append([]string(nil), keys...) {
		keys = append(keys, idx.aliases[key]...)
	}
	return uniqueStrings(keys)
}

func (idx *Index) lookupCanonical(name string, keys []string) CanonicalProduct {
	out := CanonicalProduct{Name: strings.TrimSpace(name)}
	for _, key := range keys {
		if canonical, ok := idx.canonical[key]; ok {
			out = mergeCanonicalProduct(out, canonical)
		}
	}
	if out.Name == "" {
		out.Name = strings.TrimSpace(name)
	}
	if out.Product == "" {
		out.Product = out.Name
	}
	return out
}

func (idx *Index) indexCVEIntel(intel CVEIntel) {
	id := normalizeCVE(intel.ID)
	if id == "" {
		return
	}
	keys := candidateKeys(intel.Product)
	keys = append(keys, productKeys(intel.Product)...)
	keys = append(keys, candidateKeys(intel.VendorProject+" "+intel.Product)...)
	for _, cpe := range intel.CPEs {
		keys = append(keys, cpeLookupKeys(cpe)...)
		vendor, product := cpeVendorProduct(cpe)
		keys = append(keys, productKeys(product)...)
		keys = append(keys, candidateKeys(vendor+" "+product)...)
	}
	keys = uniqueStrings(keys)
	canonical := canonicalFromCVEIntel(intel)
	for _, key := range keys {
		idx.cveByKey[key] = appendUnique(idx.cveByKey[key], id)
		idx.cpeByKey[key] = appendUnique(idx.cpeByKey[key], intel.CPEs...)
		idx.canonical[key] = mergeCanonicalProduct(idx.canonical[key], canonical)
	}
}

func canonicalFromAlias(item ProductAlias) CanonicalProduct {
	product := strings.TrimSpace(item.Product)
	if product == "" {
		product = strings.TrimSpace(item.Name)
	}
	name := productDisplayName(item.Vendor, product)
	if name == "" {
		name = strings.TrimSpace(item.Name)
	}
	return CanonicalProduct{
		Name:    name,
		Vendor:  strings.TrimSpace(item.Vendor),
		Product: product,
		Tags:    uniqueStrings(item.Tags),
		CPEs:    uniqueStrings(item.CPEs),
	}
}

func canonicalFromCVEIntel(intel CVEIntel) CanonicalProduct {
	product := strings.TrimSpace(intel.Product)
	vendor := strings.TrimSpace(intel.VendorProject)
	return CanonicalProduct{
		Name:    productDisplayName(vendor, product),
		Vendor:  vendor,
		Product: product,
		CPEs:    uniqueStrings(intel.CPEs),
	}
}

func mergeCanonicalProduct(base, addition CanonicalProduct) CanonicalProduct {
	if addition.Name != "" {
		base.Name = addition.Name
	}
	if addition.Vendor != "" {
		base.Vendor = addition.Vendor
	}
	if addition.Product != "" {
		base.Product = addition.Product
	}
	base.Tags = appendUnique(base.Tags, addition.Tags...)
	base.CPEs = appendUnique(base.CPEs, addition.CPEs...)
	return base
}

func productDisplayName(vendor, product string) string {
	vendor = strings.TrimSpace(vendor)
	product = strings.TrimSpace(product)
	if vendor == "" {
		return product
	}
	if product == "" {
		return vendor
	}
	if strings.Contains(strings.ToLower(product), strings.ToLower(vendor)) {
		return product
	}
	return vendor + " " + product
}

func cpeLookupKeys(cpe string) []string {
	cpe = strings.TrimSpace(cpe)
	if cpe == "" {
		return nil
	}
	keys := []string{normalizedCPEKey(cpe)}
	keys = append(keys, candidateKeys(cpe)...)
	vendor, product := cpeVendorProduct(cpe)
	keys = append(keys, candidateKeys(product)...)
	keys = append(keys, candidateKeys(vendor+" "+product)...)
	return uniqueStrings(keys)
}

func normalizedCPEKey(cpe string) string {
	return "cpe:" + strings.ToLower(strings.TrimSpace(cpe))
}

type rawTemplate struct {
	ID   string  `yaml:"id"`
	Info rawInfo `yaml:"info"`
}

type rawInfo struct {
	Name           string                 `yaml:"name"`
	Severity       string                 `yaml:"severity"`
	Tags           interface{}            `yaml:"tags"`
	Classification rawClassification      `yaml:"classification"`
	Metadata       map[string]interface{} `yaml:"metadata"`
}

type rawClassification struct {
	CVEID interface{} `yaml:"cve-id"`
	CWEID interface{} `yaml:"cwe-id"`
	CPE   interface{} `yaml:"cpe"`
}

func (t rawTemplate) toRef() TemplateRef {
	ref := TemplateRef{
		ID:       strings.TrimSpace(t.ID),
		Name:     strings.TrimSpace(t.Info.Name),
		Severity: normalizeSeverity(t.Info.Severity),
		Tags:     normalizeList(t.Info.Tags),
		CVEs:     normalizeCVEs(normalizeList(t.Info.Classification.CVEID)),
		CPEs:     normalizeList(t.Info.Classification.CPE),
	}
	if product, ok := metadataString(t.Info.Metadata, "product"); ok {
		ref.Product = product
	}
	if vendor, ok := metadataString(t.Info.Metadata, "vendor"); ok {
		ref.Vendor = vendor
	}
	if len(ref.CVEs) == 0 && strings.HasPrefix(strings.ToUpper(ref.ID), "CVE-") {
		ref.CVEs = []string{strings.ToUpper(ref.ID)}
	}
	if len(ref.CPEs) == 0 {
		if cpe, ok := metadataString(t.Info.Metadata, "cpe"); ok {
			ref.CPEs = []string{cpe}
		}
	}
	if ref.Product == "" || ref.Vendor == "" {
		for _, cpe := range ref.CPEs {
			vendor, product := cpeVendorProduct(cpe)
			if ref.Vendor == "" {
				ref.Vendor = vendor
			}
			if ref.Product == "" {
				ref.Product = product
			}
		}
	}
	return ref
}

func (t TemplateRef) indexKeys() []string {
	var keys []string
	keys = append(keys, productKeys(t.Product)...)
	keys = append(keys, candidateKeys(t.Vendor+" "+t.Product)...)
	for _, tag := range t.Tags {
		keys = append(keys, candidateKeys(tag)...)
	}
	for _, cpe := range t.CPEs {
		vendor, product := cpeVendorProduct(cpe)
		keys = append(keys, productKeys(product)...)
		keys = append(keys, candidateKeys(vendor+" "+product)...)
	}
	return uniqueStrings(keys)
}

func normalizeList(raw interface{}) []string {
	var out []string
	switch v := raw.(type) {
	case string:
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	case []string:
		out = append(out, v...)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return uniqueStrings(out)
}

func metadataString(metadata map[string]interface{}, key string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	raw, ok := metadata[key]
	if !ok {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v), strings.TrimSpace(v) != ""
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return strings.TrimSpace(s), strings.TrimSpace(s) != ""
			}
		}
	}
	return "", false
}

func candidateKeys(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	normalized := normalizeKey(value)
	compact := strings.ReplaceAll(normalized, " ", "")
	var keys []string
	if normalized != "" {
		keys = append(keys, normalized)
	}
	if compact != "" && compact != normalized {
		keys = append(keys, compact)
	}
	return uniqueStrings(keys)
}

func productKeys(value string) []string {
	keys := candidateKeys(value)
	normalized := normalizeKey(value)
	for _, token := range strings.Fields(normalized) {
		if isGenericProductToken(token) {
			continue
		}
		keys = append(keys, token)
	}
	return uniqueStrings(keys)
}

func isGenericProductToken(token string) bool {
	if len(token) < 3 {
		return true
	}
	switch token {
	case "server", "service", "services", "application", "platform", "system", "software",
		"enterprise", "community", "open", "source", "core", "web", "http", "https":
		return true
	default:
		return false
	}
}

func normalizeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastSpace := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func cpeVendorProduct(cpe string) (string, string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return "", ""
	}
	return strings.ReplaceAll(parts[3], "_", " "), strings.ReplaceAll(parts[4], "_", " ")
}

func normalizeSeverity(sev string) string {
	return strings.ToLower(strings.TrimSpace(sev))
}

func normalizeCVEs(values []string) []string {
	var out []string
	for _, value := range values {
		value = normalizeCVE(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func normalizeCVE(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "CVE-") {
		return ""
	}
	return value
}

func normalizeCWE(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !strings.HasPrefix(value, "CWE-") {
		return ""
	}
	return value
}

func csvColumns(header []string) map[string]int {
	cols := map[string]int{
		"cve":        -1,
		"epss":       -1,
		"percentile": -1,
	}
	for i, name := range header {
		name = strings.ToLower(strings.TrimSpace(name))
		if _, ok := cols[name]; ok {
			cols[name] = i
		}
	}
	return cols
}

func scoreTemplate(t TemplateRef) int {
	score := 0
	if len(t.CVEs) > 0 {
		score += 100
	}
	switch t.Severity {
	case "critical":
		score += 50
	case "high":
		score += 40
	case "medium":
		score += 30
	case "low":
		score += 20
	case "info":
		score += 5
	}
	if t.Product != "" {
		score += 10
	}
	return score
}

func shouldUseTemplateID(t TemplateRef) bool {
	if t.ID == "" {
		return false
	}
	if len(t.CVEs) > 0 {
		return true
	}
	switch t.Severity {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	values = uniqueStrings(values)
	sort.Strings(values)
	return values
}

func mapKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	return out
}

func appendUnique(slice []string, values ...string) []string {
	seen := make(map[string]bool, len(slice)+len(values))
	for _, value := range slice {
		seen[value] = true
	}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		slice = append(slice, value)
	}
	return slice
}

func appendUniqueInt(slice []int, value int) []int {
	for _, existing := range slice {
		if existing == value {
			return slice
		}
	}
	return append(slice, value)
}
