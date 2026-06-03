package artifact

import (
	"context"
	"encoding/json"
	"sync"

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
	TemplateID string `json:"template_id"`
	Info       string `json:"info"`
	Severity   string `json:"severity"`
	Target     string `json:"target"`
	Matched    string `json:"matched"`
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
	if n.idResolver != nil {
		if resolved, err := n.idResolver(ctx, input.Target); err == nil {
			ids = resolved
		}
	}
	if n.tagResolver != nil {
		if resolved, err := n.tagResolver(ctx, input.Target); err == nil {
			tags = resolved
		}
	}

	filters := nuclei.TemplateFilters{
		Tags: tags,
		IDs:  ids,
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(filters),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	defer ne.Close()

	ne.LoadTargets(targets, false)

	var (
		mu    sync.Mutex
		items []NucleiResultItem
	)
	err = ne.ExecuteWithCallback(func(result *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		items = append(items, NucleiResultItem{
			TemplateID: result.TemplateID,
			Info:       result.Info.Name,
			Severity:   result.Info.SeverityHolder.Severity.String(),
			Target:     result.Matched,
			Matched:    result.Matched,
		})
	})
	if err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	data, _ := json.Marshal(NucleiOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: n.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (n *NucleiArtifact) Close() error { return nil }
