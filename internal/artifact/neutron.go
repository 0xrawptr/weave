package artifact

import (
	"context"
	"encoding/json"

	sdkneutron "github.com/chainreactors/sdk/neutron"
	"github.com/chainreactors/sdk/pkg/types"
)

// NeutronArtifact wraps the SDK neutron engine for POC/template-based vulnerability detection.
type NeutronArtifact struct {
	engine *sdkneutron.Engine
}

// NeutronInput defines the input for neutron scanning.
type NeutronInput struct {
	Target  string `json:"target"`
	Payload string `json:"payload,omitempty"`
}

// NeutronOutput contains the vulnerability scan results.
type NeutronOutput struct {
	Results []NeutronResultItem `json:"results"`
	Total   int                 `json:"total"`
}

// NeutronResultItem represents a single vulnerability finding.
type NeutronResultItem struct {
	TemplateID string `json:"template_id"`
	Info       string `json:"info"`
	Severity   string `json:"severity"`
	Target     string `json:"target"`
	Matched    string `json:"matched"`
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

func (n *NeutronArtifact) Name() string { return "neutron" }

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

	neutronCtx := sdkneutron.NewContext().WithContext(ctx)
	task := sdkneutron.NewExecuteTask(nin.Target)

	resultCh, err := n.engine.Execute(neutronCtx, task)
	if err != nil {
		return Output{Artifact: n.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	var items []NeutronResultItem
	for result := range resultCh {
		if execResult, ok := types.ResultData[*sdkneutron.ExecuteResult](result); ok {
			nr := execResult.Result()
			if nr != nil {
				for _, event := range nr.Events {
					item := NeutronResultItem{Target: nin.Target}
					if event != nil {
						item.Matched = event.Matched
					}
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
