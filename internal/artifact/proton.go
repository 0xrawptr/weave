package artifact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
	sdkproton "github.com/chainreactors/sdk/proton"
)

type ProtonArtifact struct {
	engine *sdkproton.Engine
}

type ProtonInput struct {
	Mode       string `json:"mode,omitempty"`
	Data       string `json:"data,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	Label      string `json:"label,omitempty"`
}

type ProtonOutput struct {
	Results []sdkproton.Finding `json:"results"`
	Total   int                 `json:"total"`
}

func NewProtonArtifactFromEngine(engine *sdkproton.Engine) *ProtonArtifact {
	return &ProtonArtifact{engine: engine}
}

func (p *ProtonArtifact) ResizeSDKCapacity(schedulerSlots int) int {
	if p == nil || p.engine == nil || schedulerSlots <= 0 {
		return 0
	}
	return resizeSDKCapacity(p.engine, schedulerSlots)
}

func (p *ProtonArtifact) SDKCapacityTotal() int {
	if p == nil || p.engine == nil || p.engine.Capacity() == nil {
		return 0
	}
	return p.engine.Capacity().Total()
}

func (p *ProtonArtifact) Name() string { return "proton" }

func (p *ProtonArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          p.Name(),
		Consumes:      []string{"file", "data", "http_response", "raw_event"},
		Produces:      []string{"secret", "credential", "sensitive_finding"},
		Passive:       true,
		TouchesTarget: false,
		Risk:          "low",
		Description:   "SDK sensitive information matching for text and binary data",
	}
}

func (p *ProtonArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "mode", Type: "string", Required: false, Description: "Scan mode: data or block; defaults to data"},
			{Name: "data", Type: "string", Required: false, Description: "Text data to scan"},
			{Name: "data_base64", Type: "string", Required: false, Description: "Base64-encoded data for binary-safe scanning"},
			{Name: "label", Type: "string", Required: false, Description: "Source label, such as file name or response URL"},
		},
	}
}

func (p *ProtonArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "Sensitive information findings"},
			{Name: "total", Type: "int", Required: false, Description: "Number of findings"},
		},
	}
}

func (p *ProtonArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var pin ProtonInput
	if err := json.Unmarshal(input.Data, &pin); err != nil {
		return Output{Artifact: p.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	data, err := protonInputData(pin)
	if err != nil {
		return Output{Artifact: p.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	if len(data) == 0 {
		return Output{Artifact: p.Name(), Target: input.Target, Success: false, Error: "data or data_base64 is required"}, nil
	}

	label := pin.Label
	if label == "" {
		label = input.Target
	}
	if label == "" {
		label = "input"
	}

	started := time.Now()
	collector := newStatCollector(func(latest ExecutionStat, count int) {
		recordArtifactHeartbeat(ctx, p.Name(), input.Target, "sdk_stats", started, statHeartbeatFields(latest, count))
	})

	var findings []sdkproton.Finding
	switch pin.Mode {
	case "", "data":
		protonCtx := sdkproton.NewContext().WithContext(ctx).SetStatsHandler(collector.Handler())
		resultCh, err := p.engine.Execute(protonCtx, sdkproton.NewScanDataTask(data, label))
		if err != nil {
			return Output{Artifact: p.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for result := range resultCh {
			finding, ok := sdktypes.ResultData[*sdkproton.Finding](result)
			if !ok || finding == nil {
				continue
			}
			findings = append(findings, *finding)
		}
	case "block":
		findings = p.engine.ScanBlock(data, label)
	default:
		return Output{Artifact: p.Name(), Target: input.Target, Success: false, Error: "unsupported mode: " + pin.Mode}, nil
	}

	payload, _ := json.Marshal(ProtonOutput{Results: findings, Total: len(findings)})
	stats := collector.Stats()
	if len(stats) == 0 {
		stats = []ExecutionStat{{
			Engine:     p.Name(),
			Task:       pin.Mode,
			Targets:    1,
			Tasks:      1,
			Results:    int64(len(findings)),
			DurationMs: time.Since(started).Milliseconds(),
		}}
	}
	return Output{
		Artifact: p.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     payload,
		Stats:    stats,
	}, nil
}

func (p *ProtonArtifact) Close() error {
	return p.engine.Close()
}

func protonInputData(input ProtonInput) ([]byte, error) {
	if input.DataBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(input.DataBase64)
		if err != nil {
			return nil, fmt.Errorf("decode data_base64: %w", err)
		}
		return data, nil
	}
	return []byte(input.Data), nil
}
