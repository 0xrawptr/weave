package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type SubdomainArtifact struct {
	engine  *dnsx.DNSX
	threads int
}

type SubdomainInput struct {
	Domain   string   `json:"domain"`
	Wordlist []string `json:"wordlist"`
}

type SubdomainOutput struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Total  int      `json:"total"`
}

func NewSubdomainArtifact() (*SubdomainArtifact, error) {
	opts := dnsx.DefaultOptions
	opts.MaxRetries = 2
	engine, err := dnsx.New(opts)
	if err != nil {
		return nil, err
	}
	return &SubdomainArtifact{engine: engine, threads: 50}, nil
}

func (a *SubdomainArtifact) Name() string          { return "subdomain" }
func (a *SubdomainArtifact) ResizeSDKCapacity(_ int) int { return 0 }
func (a *SubdomainArtifact) SDKCapacityTotal() int      { return 0 }
func (a *SubdomainArtifact) Close() error                { return nil }

func (a *SubdomainArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          a.Name(),
		Consumes:      []string{"domain", "wordlist"},
		Produces:      []string{"ip", "domain"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "low",
		Description:   "subdomain brute-force via dnsx",
	}
}

func (a *SubdomainArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "domain", Type: "string", Required: true, Description: "Root domain to brute-force"},
			{Name: "wordlist", Type: "[]string", Required: true, Description: "Subdomain prefix wordlist"},
		},
	}
}

func (a *SubdomainArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "ips", Type: "[]string", Description: "Resolved IP addresses"},
		},
	}
}

func (a *SubdomainArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var in SubdomainInput
	if err := json.Unmarshal(input.Data, &in); err != nil {
		return Output{Artifact: a.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	domain := strings.TrimSuffix(strings.TrimSpace(in.Domain), ".")
	if domain == "" {
		return Output{Artifact: a.Name(), Target: input.Target, Success: false, Error: "domain is required"}, nil
	}

	ipSet := map[string]bool{}
	for _, word := range in.Wordlist {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		subdomain := fmt.Sprintf("%s.%s", word, domain)
		ips, err := a.engine.Lookup(subdomain)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
				continue
			}
			ipSet[ip] = true
		}
	}

done:
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	out := SubdomainOutput{Domain: domain, IPs: ips, Total: len(ipSet)}
	outData, _ := json.Marshal(out)
	return Output{
		Artifact: a.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     outData,
	}, nil
}
