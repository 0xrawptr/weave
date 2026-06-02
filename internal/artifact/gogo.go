package artifact

import (
	"context"
	"encoding/json"
	"time"

	sdkgogo "github.com/chainreactors/sdk/gogo"
	"github.com/chainreactors/sdk/pkg/types"
	"github.com/chainreactors/utils/iutils"
	"go.temporal.io/sdk/activity"
)

type GogoArtifact struct {
	engine *sdkgogo.GogoEngine
}

type GogoInput struct {
	IP    string `json:"ip"`
	Ports string `json:"ports"`
}

// GogoOutput is the full result set, persisted by the hook.
type GogoOutput struct {
	Results []*types.GOGOResult `json:"results"`
	Total   int                 `json:"total"`
}

// GogoSummary is the lightweight response for the workflow layer.
// Full results are persisted via FullData, not passed through Temporal.
type GogoSummary struct {
	Total   int      `json:"total"`
	WebURLs []string `json:"web_urls"`
}

func NewGogoArtifact(cfg *sdkgogo.Config) (*GogoArtifact, error) {
	if cfg == nil {
		cfg = sdkgogo.NewConfig()
	}
	engine := sdkgogo.NewGogoEngine(cfg)
	if err := engine.Init(); err != nil {
		return nil, err
	}
	return &GogoArtifact{engine: engine}, nil
}

func NewGogoArtifactFromEngine(engine *sdkgogo.GogoEngine) *GogoArtifact {
	return &GogoArtifact{engine: engine}
}

func (g *GogoArtifact) Name() string { return "gogo" }

func (g *GogoArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "ip", Type: "string", Required: true, Description: "Target IP or CIDR"},
			{Name: "ports", Type: "string", Required: true, Description: "Port specification"},
		},
	}
}

func (g *GogoArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "Scan results"},
			{Name: "total", Type: "int", Required: false, Description: "Total number of results"},
		},
	}
}

func (g *GogoArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var gogoIn GogoInput
	if err := json.Unmarshal(input.Data, &gogoIn); err != nil {
		return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	gogoCtx := sdkgogo.NewContext().WithContext(ctx).SetThreads(gogoThreads())
	wf := &types.Workflow{IP: gogoIn.IP, Ports: gogoIn.Ports}

	resultCh, err := g.engine.WorkflowStream(gogoCtx, wf)
	if err != nil {
		return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	var results []*types.GOGOResult
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result, ok := <-resultCh:
			if !ok {
				// Build lightweight summary for workflow, full data for persist.
				summary := GogoSummary{Total: len(results)}
				for _, r := range results {
					if r != nil && r.IsHttp() {
						summary.WebURLs = append(summary.WebURLs, r.GetBaseURL())
					}
				}
				summaryData, _ := json.Marshal(summary)
				fullData, _ := json.Marshal(GogoOutput{Results: results, Total: len(results)})
				return Output{
					Artifact: g.Name(),
					Target:   input.Target,
					Success:  true,
					Data:     summaryData,
					FullData: fullData,
				}, nil
			}
			if result != nil {
				results = append(results, result)
			}
		case <-ticker.C:
			activity.RecordHeartbeat(ctx, map[string]interface{}{
				"found": len(results),
			})
		case <-ctx.Done():
			return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: ctx.Err().Error()}, nil
		}
	}
}

func gogoThreads() int {
	if iutils.IsWin() || iutils.IsMac() {
		return 4000
	}
	n := 8000
	if fdlimit := iutils.GetFdLimit(); n > fdlimit {
		n = fdlimit - 100
	}
	return n
}

func (g *GogoArtifact) Close() error { return g.engine.Close() }
