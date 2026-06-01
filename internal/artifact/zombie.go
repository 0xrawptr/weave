package artifact

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	sdkzombie "github.com/chainreactors/sdk/zombie"
	"github.com/chainreactors/sdk/pkg/types"
)

// ZombieArtifact wraps the SDK zombie engine for service brute-force attacks.
type ZombieArtifact struct {
	engine *sdkzombie.Engine
}

// ZombieInput defines the input for brute-force operations.
type ZombieInput struct {
	Targets   []string     `json:"targets"`
	Users     []string     `json:"users,omitempty"`
	Passwords []string     `json:"passwords,omitempty"`
	Mode      string       `json:"mode"` // "clusterbomb", "pitchfork", "sniper"
	Auths     []ZombieAuth `json:"auths,omitempty"`
}

// ZombieAuth is a paired credential for pitchfork mode.
type ZombieAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ZombieOutput contains the brute-force results.
type ZombieOutput struct {
	Results []ZombieResultItem `json:"results"`
	Total   int                `json:"total"`
}

// ZombieResultItem represents a single successful credential.
type ZombieResultItem struct {
	Address  string `json:"address"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewZombieArtifact(cfg *sdkzombie.Config) (*ZombieArtifact, error) {
	if cfg == nil {
		cfg = sdkzombie.NewConfig()
	}
	engine := sdkzombie.NewEngine(cfg)
	if err := engine.Init(); err != nil {
		return nil, err
	}
	return &ZombieArtifact{engine: engine}, nil
}

// NewZombieArtifactFromEngine wraps an already-initialized SDK engine.
func NewZombieArtifactFromEngine(engine *sdkzombie.Engine) *ZombieArtifact {
	return &ZombieArtifact{engine: engine}
}

func (z *ZombieArtifact) Name() string { return "zombie" }

func (z *ZombieArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "targets", Type: "[]string", Required: true, Description: "Target addresses (host:port)"},
			{Name: "users", Type: "[]string", Required: false, Description: "Usernames for clusterbomb mode"},
			{Name: "passwords", Type: "[]string", Required: false, Description: "Passwords for clusterbomb mode"},
			{Name: "mode", Type: "string", Required: true, Description: "Brute mode: clusterbomb, pitchfork, sniper"},
			{Name: "auths", Type: "[]object", Required: false, Description: "Paired credentials for pitchfork mode"},
		},
	}
}

func (z *ZombieArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "Successful credential pairs"},
			{Name: "total", Type: "int", Required: false, Description: "Number of successful authentications"},
		},
	}
}

func parseAddress(addr string) (ip, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Try with a default port or just use as-is
		if strings.Contains(addr, ":") {
			parts := strings.SplitN(addr, ":", 2)
			return parts[0], parts[1]
		}
		return addr, ""
	}
	return host, port
}

func (z *ZombieArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var zin ZombieInput
	if err := json.Unmarshal(input.Data, &zin); err != nil {
		return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	zombieCtx := sdkzombie.NewContext().WithContext(ctx)

	// Convert string targets to zombie.Target (which is types.ZombieTarget)
	targets := make([]sdkzombie.Target, len(zin.Targets))
	for i, t := range zin.Targets {
		ip, port := parseAddress(t)
		targets[i] = sdkzombie.Target{
			IP:   ip,
			Port: port,
		}
	}

	var results []*types.ZombieResult

	switch zin.Mode {
	case "clusterbomb":
		r, err := z.engine.Brute(zombieCtx, targets, zin.Users, zin.Passwords)
		if err != nil {
			return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		results = r
	case "pitchfork":
		if len(zin.Auths) == 0 {
			return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: "pitchfork mode requires auths"}, nil
		}
		auths := make([]sdkzombie.Auth, len(zin.Auths))
		for i, a := range zin.Auths {
			auths[i] = sdkzombie.Auth{Username: a.Username, Password: a.Password}
		}
		r, err := z.engine.Pitchfork(zombieCtx, targets, auths)
		if err != nil {
			return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		results = r
	case "sniper":
		r, err := z.engine.Sniper(zombieCtx, targets)
		if err != nil {
			return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		results = r
	default:
		return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: "unsupported mode: " + zin.Mode}, nil
	}

	var items []ZombieResultItem
	for _, r := range results {
		items = append(items, ZombieResultItem{
			Address:  r.IP + ":" + r.Port,
			Service:  r.Service,
			Username: r.Username,
			Password: r.Password,
		})
	}

	data, _ := json.Marshal(ZombieOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: z.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (z *ZombieArtifact) Close() error {
	return z.engine.Close()
}
