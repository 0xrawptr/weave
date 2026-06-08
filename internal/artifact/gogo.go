package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	sdkgogo "github.com/chainreactors/sdk/gogo"
	"github.com/chainreactors/sdk/pkg/types"
	gogoutils "github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

type GogoArtifact struct {
	engine        *sdkgogo.GogoEngine
	threads       int
	resultHandler func(ctx context.Context, target, campaignID string, result *types.GOGOResult) // streaming persist
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
	return &GogoArtifact{engine: engine, threads: gogoThreads()}, nil
}

func NewGogoArtifactFromEngine(engine *sdkgogo.GogoEngine) *GogoArtifact {
	return &GogoArtifact{engine: engine, threads: gogoThreads()}
}

func (g *GogoArtifact) SetThreads(threads int) {
	if threads > 0 {
		g.threads = threads
	}
}

// SetResultHandler injects a per-result callback for streaming persist.
func (g *GogoArtifact) SetResultHandler(h func(ctx context.Context, target, campaignID string, result *types.GOGOResult)) {
	g.resultHandler = h
}

func (g *GogoArtifact) Name() string { return "gogo" }

func (g *GogoArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          g.Name(),
		Consumes:      []string{"domain", "ip", "cidr"},
		Produces:      []string{"ip", "port", "service", "fingerprint"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "medium",
		Description:   "port scan and service fingerprint discovery",
	}
}

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
	gogoIn.Ports = normalizeGogoPorts(gogoIn.Ports)
	if err := validateGogoPorts(gogoIn.Ports); err != nil {
		return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	started := time.Now()
	collector := newStatCollector(func(latest ExecutionStat, count int) {
		recordArtifactHeartbeat(ctx, g.Name(), input.Target, "sdk_stats", started, statHeartbeatFields(latest, count))
	})
	gogoCtx := sdkgogo.NewContext().WithContext(ctx).SetThreads(g.threads).SetStatsHandler(collector.Handler())
	wf := &types.Workflow{IP: gogoIn.IP, Ports: gogoIn.Ports}

	resultCh, err := g.engine.WorkflowStream(gogoCtx, wf)
	if err != nil {
		return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	var (
		count    int
		webURLs  []string
		latestIP string
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
					Stats:    collector.Stats(),
				}, nil
			}
			if result != nil {
				count++
				latestIP = result.Ip
				if result.IsHttp() {
					webURLs = append(webURLs, result.GetBaseURL())
				}
				if g.resultHandler != nil {
					g.resultHandler(ctx, input.Target, input.CampaignID, result)
				}
			}
		case <-ticker.C:
			h := map[string]interface{}{
				"found":       count,
				"elapsed_sec": int(time.Since(started).Seconds()),
				"latest":      latestIP,
			}
			if latest, statCount, ok := collector.Latest(); ok {
				for k, v := range statHeartbeatFields(latest, statCount) {
					h[k] = v
				}
			}
			if gogoIn.ChunkTotal > 0 {
				h["chunk"] = gogoIn.IP
				h["chunk_idx"] = gogoIn.ChunkIdx
				h["chunk_total"] = gogoIn.ChunkTotal
			}
			recordArtifactHeartbeat(ctx, g.Name(), input.Target, "streaming", started, h)
		case <-ctx.Done():
			return Output{Artifact: g.Name(), Target: input.Target, Success: false, Error: ctx.Err().Error()}, nil
		}
	}
}

func gogoThreads() int {
	if iutils.IsWin() || iutils.IsMac() {
		return 6000
	}
	n := 10000
	if fdlimit := iutils.GetFdLimit(); n > fdlimit {
		n = fdlimit - 100
	}
	return n
}

func normalizeGogoPorts(ports string) string {
	ports = strings.TrimSpace(ports)
	switch strings.ToLower(ports) {
	case "", "default", "top100", "top1000":
		return "top3"
	default:
		return ports
	}
}

func validateGogoPorts(ports string) error {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return fmt.Errorf("gogo ports cannot be empty")
	}
	if gogoutils.PrePort == nil {
		return nil
	}
	expanded := gogoutils.ParsePortsString(ports)
	if len(expanded) == 0 {
		return fmt.Errorf("gogo ports %q expanded to empty port set", ports)
	}
	for _, port := range expanded {
		if isGogoPseudoPort(port) {
			continue
		}
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("gogo ports %q contains unsupported port token %q", ports, port)
		}
	}
	return nil
}

func isGogoPseudoPort(port string) bool {
	switch strings.ToLower(strings.TrimSpace(port)) {
	case "icmp", "ping", "oxid":
		return true
	default:
		return false
	}
}

func (g *GogoArtifact) Close() error { return g.engine.Close() }
