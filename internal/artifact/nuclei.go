package artifact

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NucleiArtifact wraps the nuclei engine for template-based vulnerability scanning.
type NucleiArtifact struct {
	urlResolver URLResolver
	tagResolver TagResolver
	idResolver  TagResolver // returns template IDs for precise matching
}

// NucleiInput defines the input for nuclei scanning.
type NucleiInput struct {
	Targets []string `json:"targets,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	IDs     []string `json:"ids,omitempty"`
}

// NucleiOutput contains the scan results.
type NucleiOutput struct {
	Results []NucleiResultItem `json:"results"`
	Total   int                `json:"total"`
}

// NucleiResultItem represents a single finding.
type NucleiResultItem struct {
	TemplateID    string                 `json:"template_id"`
	TemplatePath  string                 `json:"template_path,omitempty"`
	TemplateURL   string                 `json:"template_url,omitempty"`
	Info          string                 `json:"info"`
	Severity      string                 `json:"severity"`
	Tags          []string               `json:"tags,omitempty"`
	Target        string                 `json:"target"`
	Matched       string                 `json:"matched"`
	Type          string                 `json:"type,omitempty"`
	MatcherName   string                 `json:"matcher_name,omitempty"`
	ExtractorName string                 `json:"extractor_name,omitempty"`
	Host          string                 `json:"host,omitempty"`
	IP            string                 `json:"ip,omitempty"`
	Port          string                 `json:"port,omitempty"`
	Scheme        string                 `json:"scheme,omitempty"`
	URL           string                 `json:"url,omitempty"`
	Path          string                 `json:"path,omitempty"`
	CVEs          []string               `json:"cves,omitempty"`
	CWEs          []string               `json:"cwes,omitempty"`
	CPE           string                 `json:"cpe,omitempty"`
	CVSSScore     float64                `json:"cvss_score,omitempty"`
	EPSSScore     float64                `json:"epss_score,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

func NewNucleiArtifact() (*NucleiArtifact, error) {
	return &NucleiArtifact{}, nil
}

func (n *NucleiArtifact) Name() string { return "nuclei" }

func (n *NucleiArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          n.Name(),
		Consumes:      []string{"url", "template", "tag"},
		Produces:      []string{"vulnerability"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "medium",
		Description:   "template-based vulnerability validation",
	}
}

func (n *NucleiArtifact) SetURLResolver(r URLResolver) { n.urlResolver = r }
func (n *NucleiArtifact) SetTagResolver(r TagResolver) { n.tagResolver = r }
func (n *NucleiArtifact) SetIDResolver(r TagResolver)  { n.idResolver = r }

func (n *NucleiArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "targets", Type: "[]string", Required: false, Description: "Target URLs or hosts"},
			{Name: "tags", Type: "[]string", Required: false, Description: "Filter templates by tags"},
			{Name: "ids", Type: "[]string", Required: false, Description: "Filter templates by IDs"},
		},
	}
}

func (n *NucleiArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "Vulnerability findings"},
			{Name: "total", Type: "int", Required: false, Description: "Number of findings"},
		},
	}
}

func (n *NucleiArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	started := time.Now()
	var nin NucleiInput
	if err := json.Unmarshal(input.Data, &nin); err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	targets := nin.Targets
	if len(targets) == 0 && n.urlResolver != nil {
		if resolved, err := n.urlResolver(ctx, input.Target); err == nil {
			targets = resolved
		}
	}
	if len(targets) == 0 {
		return Output{Artifact: n.Name(), Target: input.Target, Success: true}, nil
	}

	tags := nin.Tags
	ids := nin.IDs
	if len(ids) == 0 && n.idResolver != nil {
		if resolved, err := n.idResolver(ctx, input.Target); err == nil {
			ids = resolved
		}
	}
	if len(tags) == 0 && n.tagResolver != nil {
		if resolved, err := n.tagResolver(ctx, input.Target); err == nil {
			tags = resolved
		}
	}

	filters := nuclei.TemplateFilters{
		Tags: tags,
		IDs:  ids,
	}
	recordArtifactHeartbeat(ctx, n.Name(), input.Target, "loading", started, map[string]interface{}{
		"targets": len(targets),
		"tags":    len(tags),
		"ids":     len(ids),
	})

	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(filters),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		if isNucleiNoTemplatesError(err) {
			data, _ := json.Marshal(NucleiOutput{Results: nil, Total: 0})
			recordArtifactHeartbeat(ctx, n.Name(), input.Target, "skipped", started, map[string]interface{}{
				"reason":  "no_templates_available",
				"targets": len(targets),
				"tags":    len(tags),
				"ids":     len(ids),
			})
			return Output{Artifact: n.Name(), Target: input.Target, Success: true, Data: data}, nil
		}
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	defer ne.Close()

	ne.LoadTargets(targets, false)
	recordArtifactHeartbeat(ctx, n.Name(), input.Target, "executing", started, map[string]interface{}{
		"targets": len(targets),
		"tags":    len(tags),
		"ids":     len(ids),
	})

	var (
		mu    sync.Mutex
		items []NucleiResultItem
	)
	err = ne.ExecuteWithCallback(func(result *output.ResultEvent) {
		if !acceptNucleiResult(result) {
			return
		}
		var count int
		mu.Lock()
		items = append(items, NucleiResultItem{
			TemplateID:    result.TemplateID,
			TemplatePath:  result.TemplatePath,
			TemplateURL:   result.TemplateURL,
			Info:          result.Info.Name,
			Severity:      result.Info.SeverityHolder.Severity.String(),
			Tags:          append([]string{}, result.Info.Tags.ToSlice()...),
			Target:        nucleiFirstNonEmpty(result.URL, result.Host, result.Matched),
			Matched:       result.Matched,
			Type:          result.Type,
			MatcherName:   result.MatcherName,
			ExtractorName: result.ExtractorName,
			Host:          result.Host,
			IP:            result.IP,
			Port:          result.Port,
			Scheme:        result.Scheme,
			URL:           result.URL,
			Path:          result.Path,
			Metadata:      result.Metadata,
		})
		if result.Info.Classification != nil {
			item := &items[len(items)-1]
			item.CVEs = append([]string{}, result.Info.Classification.CVEID.ToSlice()...)
			item.CWEs = append([]string{}, result.Info.Classification.CWEID.ToSlice()...)
			item.CPE = result.Info.Classification.CPE
			item.CVSSScore = result.Info.Classification.CVSSScore
			item.EPSSScore = result.Info.Classification.EPSSScore
		}
		count = len(items)
		mu.Unlock()
		recordArtifactHeartbeat(ctx, n.Name(), input.Target, "finding", started, map[string]interface{}{
			"findings":      count,
			"last_template": result.TemplateID,
			"last_target":   nucleiFirstNonEmpty(result.URL, result.Host, result.Matched),
			"last_severity": result.Info.SeverityHolder.Severity.String(),
		})
	})
	if err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	recordArtifactHeartbeat(ctx, n.Name(), input.Target, "completed", started, map[string]interface{}{
		"findings": len(items),
		"targets":  len(targets),
		"tags":     len(tags),
		"ids":      len(ids),
	})

	data, _ := json.Marshal(NucleiOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: n.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (n *NucleiArtifact) Close() error { return nil }

func isNucleiNoTemplatesError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "no templates available") ||
		strings.Contains(value, "no templates provided") ||
		strings.Contains(value, "no templates found")
}

func acceptNucleiResult(result *output.ResultEvent) bool {
	if result == nil {
		return false
	}
	templateID := strings.TrimSpace(result.TemplateID)
	if templateID == "" || strings.HasPrefix(templateID, "cluster-") {
		return false
	}
	if strings.TrimSpace(result.Info.Name) == "" {
		return false
	}
	return true
}

func nucleiFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
