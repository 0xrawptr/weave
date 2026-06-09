package artifact

import (
	"context"
	"encoding/json"

	sdkneutron "github.com/chainreactors/sdk/neutron"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
)

// NeutronArtifact wraps the SDK neutron engine for POC/template-based vulnerability detection.
type NeutronArtifact struct {
	engine      *sdkneutron.Engine
	urlResolver URLResolver
}

// NeutronInput defines the input for neutron scanning.
type NeutronInput struct {
	Target  string `json:"target"`
	Payload string `json:"payload,omitempty"`
}

// NeutronOutput contains the vulnerability scan results.
type NeutronOutput struct {
	Results []*sdktypes.VulnResult `json:"results"`
	Total   int                    `json:"total"`
}

func NewNeutronArtifact(cfg *sdkneutron.Config) (*NeutronArtifact, error) {
	if cfg == nil {
		cfg = &sdkneutron.Config{}
	}
	engine, err := sdkneutron.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	return &NeutronArtifact{engine: engine}, nil
}

// NewNeutronArtifactFromEngine wraps an already-initialized SDK engine.
func NewNeutronArtifactFromEngine(engine *sdkneutron.Engine) *NeutronArtifact {
	return &NeutronArtifact{engine: engine}
}

// SetURLResolver injects a resolver for DB-backed URL resolution.
func (n *NeutronArtifact) SetURLResolver(r URLResolver) { n.urlResolver = r }

func (n *NeutronArtifact) Name() string { return "neutron" }

func (n *NeutronArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          n.Name(),
		Consumes:      []string{"url"},
		Produces:      []string{"vulnerability"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "medium",
		Description:   "SDK POC/template vulnerability validation",
	}
}

func (n *NeutronArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "target", Type: "string", Required: true, Description: "Target URL or host"},
			{Name: "payload", Type: "string", Required: false, Description: "Custom variable payload string"},
		},
	}
}

func (n *NeutronArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "Vulnerability findings"},
			{Name: "total", Type: "int", Required: false, Description: "Number of findings"},
		},
	}
}

func (n *NeutronArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var nin NeutronInput
	if err := json.Unmarshal(input.Data, &nin); err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	if nin.Target == "" {
		nin.Target = input.Target
	}

	// Resolve targets: single URL or DB-backed bulk scan.
	targets := []string{nin.Target}
	if n.urlResolver != nil {
		if resolved, err := n.urlResolver(ctx, input.Target); err == nil && len(resolved) > 0 {
			targets = resolved
		}
	}

	neutronCtx := sdkneutron.NewContext().WithContext(ctx)
	var items []*sdktypes.VulnResult

	for _, t := range targets {
		task := sdkneutron.NewExecuteTask(t)
		resultCh, err := n.engine.Execute(neutronCtx, task)
		if err != nil {
			continue
		}
		for result := range resultCh {
			if execResult, ok := sdktypes.ResultData[*sdkneutron.ExecuteResult](result); ok {
				item := execResult.VulnResult(t)
				if item != nil && item.Matched {
					items = append(items, item)
				}
			}
		}
	}

	data, _ := json.Marshal(NeutronOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: n.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (n *NeutronArtifact) Close() error {
	return n.engine.Close()
}
