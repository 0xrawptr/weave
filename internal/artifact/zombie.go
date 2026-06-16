package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
	sdkzombie "github.com/chainreactors/sdk/zombie"
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

// NewZombieArtifactFromEngine wraps an already-initialized SDK engine.
func NewZombieArtifactFromEngine(engine *sdkzombie.Engine) *ZombieArtifact {
	return &ZombieArtifact{engine: engine}
}

func (z *ZombieArtifact) Name() string { return "zombie" }

func (z *ZombieArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          z.Name(),
		Consumes:      []string{"service", "credential_dictionary"},
		Produces:      []string{"credential"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "high",
		Description:   "service credential brute-force validation",
	}
}

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
		if strings.Contains(addr, ":") {
			parts := strings.SplitN(addr, ":", 2)
			return parts[0], parts[1]
		}
		return addr, ""
	}
	return host, port
}

func parseZombieTarget(raw string) sdkzombie.Target {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return sdkzombie.Target{}
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		host, port := parseAddress(parsed.Host)
		service := strings.ToLower(parsed.Scheme)
		return sdkzombie.Target{IP: host, Port: port, Service: service, Scheme: service}
	}
	ip, port := parseAddress(raw)
	return sdkzombie.Target{IP: ip, Port: port, Service: zombieServiceForPort(port)}
}

func zombieServiceForPort(port string) string {
	switch strings.TrimSpace(port) {
	case "21":
		return "ftp"
	case "22":
		return "ssh"
	case "23":
		return "telnet"
	case "80":
		return "http"
	case "110":
		return "pop3"
	case "161":
		return "snmp"
	case "389":
		return "ldap"
	case "443":
		return "https"
	case "445":
		return "smb"
	case "873":
		return "rsync"
	case "1433":
		return "mssql"
	case "1521":
		return "oracle"
	case "1883":
		return "mqtt"
	case "2181":
		return "zookeeper"
	case "3306":
		return "mysql"
	case "3389":
		return "rdp"
	case "5432":
		return "postgresql"
	case "5672":
		return "amqp"
	case "5900":
		return "vnc"
	case "6379":
		return "redis"
	case "8080":
		return "http_proxy"
	case "1080":
		return "socks5"
	case "11211":
		return "memcached"
	case "27017":
		return "mongo"
	default:
		return ""
	}
}

func (z *ZombieArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var zin ZombieInput
	if err := json.Unmarshal(input.Data, &zin); err != nil {
		return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	started := time.Now()
	collector := newStatCollector(func(latest ExecutionStat, count int) {
		recordArtifactHeartbeat(ctx, z.Name(), input.Target, "sdk_stats", started, statHeartbeatFields(latest, count))
	})
	zombieCtx := sdkzombie.NewContext().WithContext(ctx).SetStatsHandler(collector.Handler())

	targets := make([]sdkzombie.Target, len(zin.Targets))
	for i, t := range zin.Targets {
		targets[i] = parseZombieTarget(t)
	}

	task := sdkzombie.NewBruteTask(targets)
	task.Users = append([]string(nil), zin.Users...)
	task.Passwords = append([]string(nil), zin.Passwords...)
	zombieOpt := sdktypes.NewDefaultZombieOption()
	switch zin.Mode {
	case "", "clusterbomb", "brute", "bomb":
		zombieOpt.Mod = sdktypes.ZombieModeBomb
		recordArtifactHeartbeat(ctx, z.Name(), input.Target, "clusterbomb", started, map[string]interface{}{
			"targets":   len(targets),
			"users":     len(zin.Users),
			"passwords": len(zin.Passwords),
		})
	case "pitchfork":
		if len(zin.Auths) == 0 {
			return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: "pitchfork mode requires auths"}, nil
		}
		zombieOpt.Mod = sdktypes.ZombieModePitchFork
		recordArtifactHeartbeat(ctx, z.Name(), input.Target, "pitchfork", started, map[string]interface{}{
			"targets": len(targets),
			"auths":   len(zin.Auths),
		})
		task.Auths = make([]sdkzombie.Auth, len(zin.Auths))
		for i, a := range zin.Auths {
			task.Auths[i] = sdkzombie.Auth{Username: a.Username, Password: a.Password}
		}
	case "sniper":
		zombieOpt.Mod = sdktypes.ZombieModeSniper
		recordArtifactHeartbeat(ctx, z.Name(), input.Target, "sniper", started, map[string]interface{}{
			"targets": len(targets),
		})
		applySniperAuths(task.Targets, zin.Auths)
	default:
		return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: "unsupported mode: " + zin.Mode}, nil
	}
	zombieCtx.SetOption(zombieOpt)

	var items []ZombieResultItem
	resultCh, err := z.engine.Execute(zombieCtx, task)
	if err != nil {
		return Output{Artifact: z.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	for result := range resultCh {
		if result.Error() != nil {
			recordArtifactHeartbeat(ctx, z.Name(), input.Target, "result_error", started, map[string]interface{}{
				"error": result.Error().Error(),
			})
			continue
		}
		r, ok := sdktypes.ResultData[*sdktypes.ZombieResult](result)
		if !ok || r == nil {
			continue
		}
		items = append(items, zombieResultItem(r))
	}
	recordArtifactHeartbeat(ctx, z.Name(), input.Target, "completed", started, map[string]interface{}{
		"results": len(items),
	})

	data, _ := json.Marshal(ZombieOutput{Results: items, Total: len(items)})
	return Output{
		Artifact: z.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
		Stats:    collector.Stats(),
	}, nil
}

func applySniperAuths(targets []sdkzombie.Target, auths []ZombieAuth) {
	if len(auths) == 0 {
		return
	}
	if len(auths) == 1 {
		for i := range targets {
			targets[i].Username = auths[0].Username
			targets[i].Password = auths[0].Password
		}
		return
	}
	for i := range targets {
		if i >= len(auths) {
			return
		}
		targets[i].Username = auths[i].Username
		targets[i].Password = auths[i].Password
	}
}

func zombieResultItem(r *sdktypes.ZombieResult) ZombieResultItem {
	address := r.IP
	if r.Port != "" {
		address = net.JoinHostPort(r.IP, r.Port)
		if strings.HasPrefix(address, "[") && net.ParseIP(r.IP) == nil {
			address = fmt.Sprintf("%s:%s", r.IP, r.Port)
		}
	}
	return ZombieResultItem{
		Address:  address,
		Service:  r.Service,
		Username: r.Username,
		Password: r.Password,
	}
}

func (z *ZombieArtifact) Close() error {
	return z.engine.Close()
}
