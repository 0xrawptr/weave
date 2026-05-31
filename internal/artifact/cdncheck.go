package artifact

import (
	"context"
	"encoding/json"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

// CdncheckArtifact wraps the cdncheck library for CDN/WAF/Cloud detection.
type CdncheckArtifact struct {
	client *cdncheck.Client
}

// CdncheckInput accepts either a domain or an IP.
type CdncheckInput struct {
	Target string `json:"target"` // domain or IP
}

// CdncheckOutput describes what type of infrastructure was detected.
type CdncheckOutput struct {
	IsCDN   bool   `json:"is_cdn"`
	IsCloud bool   `json:"is_cloud"`
	IsWAF   bool   `json:"is_waf"`
	CDNName string `json:"cdn_name,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

func NewCdncheckArtifact() (*CdncheckArtifact, error) {
	client, err := cdncheck.NewWithOpts(3, nil)
	if err != nil {
		return nil, err
	}
	return &CdncheckArtifact{client: client}, nil
}

func (c *CdncheckArtifact) Name() string { return "cdncheck" }

func (c *CdncheckArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "target", Type: "string", Required: true, Description: "Domain or IP to check"},
		},
	}
}

func (c *CdncheckArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "is_cdn", Type: "bool", Required: false},
			{Name: "is_cloud", Type: "bool", Required: false},
			{Name: "is_waf", Type: "bool", Required: false},
			{Name: "cdn_name", Type: "string", Required: false},
			{Name: "ips", Type: "[]string", Required: false, Description: "Resolved IPs"},
		},
	}
}

func (c *CdncheckArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var in CdncheckInput
	if err := json.Unmarshal(input.Data, &in); err != nil {
		return Output{Artifact: c.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	target := in.Target

	// If target looks like an IP address, check directly.
	if ip := net.ParseIP(target); ip != nil {
		matched, name, itemType, err := c.client.Check(ip)
		if err != nil {
			return Output{Artifact: c.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		return c.buildOutput(input.Target, matched, name, itemType, []string{target}), nil
	}

	// Domain: resolve DNS and check all records including CNAME fallback.
	matched, name, itemType, err := c.client.CheckDomainWithFallback(target)
	if err != nil {
		return Output{Artifact: c.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	// Grab resolved IPs for the output.
	var ips []string
	if dnsData, err := c.client.GetDnsData(target); err == nil && dnsData != nil {
		ips = append(ips, dnsData.A...)
		ips = append(ips, dnsData.AAAA...)
	}

	return c.buildOutput(input.Target, matched, name, itemType, ips), nil
}

func (c *CdncheckArtifact) buildOutput(target string, matched bool, name, itemType string, ips []string) Output {
	out := CdncheckOutput{
		CDNName: name,
		IPs:     ips,
	}
	switch itemType {
	case "cdn":
		out.IsCDN = matched
	case "cloud":
		out.IsCloud = matched
	case "waf":
		out.IsWAF = matched
	}
	data, _ := json.Marshal(out)
	return Output{
		Artifact: c.Name(),
		Target:   target,
		Success:  true,
		Data:     data,
	}
}

func (c *CdncheckArtifact) Close() error { return nil }
