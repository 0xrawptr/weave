package artifact

import (
	"context"
	"encoding/json"

	sdkspray "github.com/chainreactors/sdk/spray"
)

// SprayArtifact wraps the SDK spray engine for HTTP path fuzzing and URL discovery.
type SprayArtifact struct {
	engine *sdkspray.SprayEngine
}

// SprayInput defines the input for spray operations.
type SprayInput struct {
	URLs     []string `json:"urls,omitempty"`     // for check mode
	BaseURLs []string `json:"base_urls,omitempty"` // for brute mode
	Wordlist []string `json:"wordlist,omitempty"`  // for brute mode
}

// SprayOutput contains the spray results.
type SprayOutput struct {
	Results []SprayResultItem `json:"results"`
	Total   int               `json:"total"`
}

// SprayResultItem is a flattened spray result.
type SprayResultItem struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

func NewSprayArtifact(cfg *sdkspray.Config) (*SprayArtifact, error) {
	if cfg == nil {
		cfg = sdkspray.NewConfig()
	}
	engine := sdkspray.NewSprayEngine(cfg)
	if err := engine.Init(); err != nil {
		return nil, err
	}
	return &SprayArtifact{engine: engine}, nil
}

func (s *SprayArtifact) Name() string { return "spray" }

func (s *SprayArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "urls", Type: "[]string", Required: false, Description: "URLs to check"},
			{Name: "base_urls", Type: "[]string", Required: false, Description: "Base URLs for brute force"},
			{Name: "wordlist", Type: "[]string", Required: false, Description: "Wordlist for path brute force"},
		},
	}
}

func (s *SprayArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "URL check or brute results"},
			{Name: "total", Type: "int", Required: false, Description: "Total number of results"},
		},
	}
}

func (s *SprayArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var sprayIn SprayInput
	if err := json.Unmarshal(input.Data, &sprayIn); err != nil {
		return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	sprayCtx := sdkspray.NewContext().WithContext(ctx)

	var items []SprayResultItem

	if len(sprayIn.BaseURLs) > 0 && len(sprayIn.Wordlist) > 0 {
		results, err := s.engine.BruteMany(sprayCtx, sprayIn.BaseURLs, sprayIn.Wordlist)
		if err != nil {
			return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for _, r := range results {
			items = append(items, SprayResultItem{
				URL:        r.UrlString,
				StatusCode: r.Status,
			})
		}
	} else if len(sprayIn.URLs) > 0 {
		results, err := s.engine.Check(sprayCtx, sprayIn.URLs)
		if err != nil {
			return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for _, r := range results {
			items = append(items, SprayResultItem{
				URL:        r.UrlString,
				StatusCode: r.Status,
			})
		}
	} else {
		return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: "no valid input: provide urls or base_urls+wordlist"}, nil
	}

	data, _ := json.Marshal(SprayOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: s.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (s *SprayArtifact) Close() error {
	return s.engine.Close()
}
