package artifact

import (
	"context"
	"encoding/json"

	sdkfingers "github.com/chainreactors/sdk/fingers"
)

// FingersArtifact wraps the SDK fingers engine for passive and active fingerprinting.
type FingersArtifact struct {
	engine *sdkfingers.Engine
}

// FingersInput defines the input for fingerprint operations.
type FingersInput struct {
	Mode string   `json:"mode"` // "match", "http_match"
	Data []byte   `json:"data,omitempty"`
	URLs []string `json:"urls,omitempty"`
}

// FingersOutput contains the fingerprinted frameworks.
type FingersOutput struct {
	Frameworks []FingersFrameworkItem `json:"frameworks"`
	Count      int                    `json:"count"`
}

type FingersFrameworkItem struct {
	Name    string   `json:"name"`
	Product string   `json:"product,omitempty"`
	Version string   `json:"version,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

func NewFingersArtifact(cfg *sdkfingers.Config) (*FingersArtifact, error) {
	if cfg == nil {
		cfg = sdkfingers.NewConfig()
	}
	engine, err := sdkfingers.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	return &FingersArtifact{engine: engine}, nil
}

func (f *FingersArtifact) Name() string { return "fingers" }

func (f *FingersArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "mode", Type: "string", Required: true, Description: "Scan mode: match, http_match"},
			{Name: "data", Type: "bytes", Required: false, Description: "Raw HTTP response data (for match mode)"},
			{Name: "urls", Type: "[]string", Required: false, Description: "Target URLs (for http_match mode)"},
		},
	}
}

func (f *FingersArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "frameworks", Type: "array", Required: false, Description: "Matched fingerprint frameworks"},
			{Name: "count", Type: "int", Required: false, Description: "Number of matched frameworks"},
		},
	}
}

func (f *FingersArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var fin FingersInput
	if err := json.Unmarshal(input.Data, &fin); err != nil {
		return Output{Artifact: f.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	var items []FingersFrameworkItem

	switch fin.Mode {
	case "match":
		frameworks, err := f.engine.Match(fin.Data)
		if err != nil {
			return Output{Artifact: f.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for name, fw := range frameworks {
			item := FingersFrameworkItem{Name: name}
			if fw != nil {
				item.Product = fw.Product
				item.Version = fw.Version
				item.Tags = fw.Tags
			}
			items = append(items, item)
		}
	case "http_match":
		fingersCtx := sdkfingers.NewContext().WithContext(ctx)
		results, err := f.engine.HTTPMatch(fingersCtx, fin.URLs)
		if err != nil {
			return Output{Artifact: f.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for _, tr := range results {
			for _, sr := range tr.Results {
				item := FingersFrameworkItem{Name: sr.Framework.Name}
				if sr.Framework != nil {
					item.Product = sr.Framework.Product
					item.Version = sr.Framework.Version
					item.Tags = sr.Framework.Tags
				}
				items = append(items, item)
			}
		}
	default:
		return Output{Artifact: f.Name(), Target: input.Target, Success: false, Error: "unsupported mode: " + fin.Mode}, nil
	}

	data, _ := json.Marshal(FingersOutput{Frameworks: items, Count: len(items)})
	return Output{
		Artifact: f.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (f *FingersArtifact) Close() error {
	return f.engine.Close()
}
