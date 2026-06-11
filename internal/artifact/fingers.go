package artifact

import (
	"context"
	"encoding/json"
	"sort"

	fingerscommon "github.com/chainreactors/fingers/common"
	sdkfingers "github.com/chainreactors/sdk/fingers"

	"github.com/0xrawptr/weave/internal/favicon"
)

type FingersArtifact struct {
	engine      *sdkfingers.Engine
	urlResolver URLResolver
}

type FingersInput struct {
	Mode string   `json:"mode"`
	Data []byte   `json:"data,omitempty"`
	URLs []string `json:"urls,omitempty"`
}

type FingersOutput struct {
	Frameworks []FingersFrameworkItem `json:"frameworks"`
	Count      int                    `json:"count"`
}

type FingersFrameworkItem struct {
	Name        string              `json:"name"`
	Target      string              `json:"target,omitempty"`
	Product     string              `json:"product,omitempty"`
	Version     string              `json:"version,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Sources     []string            `json:"sources,omitempty"`
	CPE         string              `json:"cpe,omitempty"`
	Focus       bool                `json:"focus,omitempty"`
	MatchDetail *FingersMatchDetail `json:"match_detail,omitempty"`
}

type FingersMatchDetail struct {
	RuleIndex    int    `json:"rule_index,omitempty"`
	MatcherType  string `json:"matcher_type,omitempty"`
	MatcherIndex int    `json:"matcher_index,omitempty"`
	MatcherValue string `json:"matcher_value,omitempty"`
	SendData     string `json:"send_data,omitempty"`
}

func NewFingersArtifactFromEngine(engine *sdkfingers.Engine) *FingersArtifact {
	return &FingersArtifact{engine: engine}
}

func (f *FingersArtifact) SetURLResolver(r URLResolver) { f.urlResolver = r }

func (f *FingersArtifact) Name() string { return "fingers" }

func (f *FingersArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          f.Name(),
		Consumes:      []string{"url", "http_response"},
		Produces:      []string{"fingerprint"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "low",
		Description:   "HTTP fingerprint matching and favicon detection",
	}
}

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
			items = append(items, frameworkItem(input.Target, name, fw))
		}
	case "http_match":
		urls := fin.URLs
		if len(urls) == 0 && f.urlResolver != nil {
			if resolved, err := f.urlResolver(ctx, input.Target); err == nil {
				urls = resolved
			}
		}
		fingersCtx := sdkfingers.NewContext().WithContext(ctx)
		results, err := f.engine.HTTPMatch(fingersCtx, urls)
		if err != nil {
			return Output{Artifact: f.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for _, tr := range results {
			for _, sr := range tr.Results {
				if sr.Framework == nil {
					continue
				}
				items = append(items, frameworkItem(tr.Target, sr.Framework.Name, sr.Framework))
			}
		}
		// Favicon detection with smarter HTML parsing.
		fc := favicon.NewFetcher()
		for _, u := range urls {
			r, err := fc.Fetch(u)
			if err != nil || len(r.Data) == 0 {
				continue
			}
			frameworks, err := f.engine.MatchFavicon(r.Data)
			if err != nil {
				continue
			}
			for name, fw := range frameworks {
				if fw == nil {
					continue
				}
				item := frameworkItem(u, name, fw)
				if len(item.Sources) == 0 {
					item.Sources = []string{"ico"}
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

func frameworkItem(target, name string, fw *fingerscommon.Framework) FingersFrameworkItem {
	item := FingersFrameworkItem{Name: name, Target: target}
	if fw == nil {
		return item
	}
	item.Product = fw.Product
	item.Version = fw.Version
	item.Tags = fw.Tags
	item.Focus = fw.IsFocus
	if fw.Attributes != nil {
		item.CPE = fw.CPE()
	}
	for from := range fw.Froms {
		item.Sources = append(item.Sources, from.String())
	}
	sort.Strings(item.Sources)
	if fw.MatchDetail != nil {
		item.MatchDetail = &FingersMatchDetail{
			RuleIndex:    fw.MatchDetail.RuleIndex,
			MatcherType:  fw.MatchDetail.MatcherType,
			MatcherIndex: fw.MatchDetail.MatcherIndex,
			MatcherValue: fw.MatchDetail.MatcherValue,
			SendData:     fw.MatchDetail.SendData,
		}
	}
	return item
}
