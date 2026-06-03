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
	engine        *sdkgogo.GogoEngine
	resultHandler func(ctx context.Context, target string, result *types.GOGOResult) // streaming persist
}

type GogoInput struct {
	IP         string `json:"ip"`
	Ports      string `json:"ports"`
	ChunkIdx   int    `json:"chunk_idx,omitempty"`
	ChunkTotal int    `json:"chunk_total,omitempty"`
}

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

// SetResultHandler injects a per-result callback for streaming persist.
func (g *GogoArtifact) SetResultHandler(h func(ctx context.Context, target string, result *types.GOGOResult)) {
	g.resultHandler = h
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

	var (
		count    int
		webURLs  []string
		latestIP string
		started  = time.Now()
	)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result, ok := <-resultCh:
			if !ok {
				summaryData, _ := json.Marshal(GogoSummary{Total: count, WebURLs: webURLs})
				return Output{
					Artifact: g.Name(),
					Target:   input.Target,
					Success:  true,
					Data:     summaryData,
				}, nil
			}
			if result != nil {
				count++
				latestIP = result.Ip
				if result.IsHttp() {
					webURLs = append(webURLs, result.GetBaseURL())
				}
				if g.resultHandler != nil {
					g.resultHandler(ctx, input.Target, result)
				}
			}
		case <-ticker.C:
			h := map[string]interface{}{
				"found":       count,
				"elapsed_sec": int(time.Since(started).Seconds()),
				"latest":      latestIP,
			}
			if gogoIn.ChunkTotal > 0 {
				h["chunk"] = gogoIn.IP
				h["chunk_idx"] = gogoIn.ChunkIdx
				h["chunk_total"] = gogoIn.ChunkTotal
			}
			activity.RecordHeartbeat(ctx, h)
		case <-ctx.Done():
			return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: ctx.Err().Error()}, nil
		}
	}
}

func gogoThreads() int {
	if iutils.IsWin() || iutils.IsMac() {
		return 100
	}
	n := 10000
	if fdlimit := iutils.GetFdLimit(); n > fdlimit {
		n = fdlimit - 100
	}
	return n
}

func (g *GogoArtifact) Close() error { return g.engine.Close() }
