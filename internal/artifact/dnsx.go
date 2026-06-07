package artifact

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	miekgdns "github.com/miekg/dns"
	dnsxlib "github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/retryabledns"
)

type DNSXArtifact struct{}

type DNSXInput struct {
	Target      string   `json:"target"`
	Targets     []string `json:"targets,omitempty"`
	Resolvers   []string `json:"resolvers,omitempty"`
	RecordTypes []string `json:"record_types,omitempty"`
	QueryAll    bool     `json:"query_all,omitempty"`
	MaxRetries  int      `json:"max_retries,omitempty"`
}

type DNSXOutput struct {
	Results []DNSXResult `json:"results"`
	Total   int          `json:"total"`
}

type DNSXResult struct {
	Host           string   `json:"host"`
	TTL            uint32   `json:"ttl,omitempty"`
	Resolver       []string `json:"resolver,omitempty"`
	A              []string `json:"a,omitempty"`
	AAAA           []string `json:"aaaa,omitempty"`
	CNAME          []string `json:"cname,omitempty"`
	MX             []string `json:"mx,omitempty"`
	PTR            []string `json:"ptr,omitempty"`
	SOA            []string `json:"soa,omitempty"`
	NS             []string `json:"ns,omitempty"`
	TXT            []string `json:"txt,omitempty"`
	SRV            []string `json:"srv,omitempty"`
	CAA            []string `json:"caa,omitempty"`
	AllRecords     []string `json:"all,omitempty"`
	StatusCode     string   `json:"status_code,omitempty"`
	StatusCodeRaw  int      `json:"status_code_raw,omitempty"`
	HasInternalIPs bool     `json:"has_internal_ips,omitempty"`
	InternalIPs    []string `json:"internal_ips,omitempty"`
	Error          string   `json:"error,omitempty"`
}

func NewDNSXArtifact() (*DNSXArtifact, error) {
	return &DNSXArtifact{}, nil
}

func (d *DNSXArtifact) Name() string { return "dnsx" }

func (d *DNSXArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          d.Name(),
		Consumes:      []string{"domain", "subdomain", "ip"},
		Produces:      []string{"ip", "dns_record"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "low",
		Description:   "DNS resolution and record enumeration through projectdiscovery/dnsx",
	}
}

func (d *DNSXArtifact) InputSchema() InputSchema {
	return InputSchema{Fields: []SchemaField{
		{Name: "target", Type: "string", Required: true, Description: "Domain, subdomain, or IP to resolve"},
		{Name: "targets", Type: "[]string", Required: false, Description: "Optional bulk targets"},
		{Name: "resolvers", Type: "[]string", Required: false, Description: "Resolvers such as udp:1.1.1.1:53"},
		{Name: "record_types", Type: "[]string", Required: false, Description: "DNS record types: a, aaaa, cname, ns, mx, txt, ptr, soa, srv, caa"},
		{Name: "query_all", Type: "bool", Required: false, Description: "Use dnsx query-all behavior"},
		{Name: "max_retries", Type: "int", Required: false, Description: "DNS retry count"},
	}}
}

func (d *DNSXArtifact) OutputSchema() OutputSchema {
	return OutputSchema{Fields: []SchemaField{
		{Name: "results", Type: "array", Required: false, Description: "DNS query results"},
		{Name: "total", Type: "int", Required: false, Description: "Number of result rows"},
	}}
}

func (d *DNSXArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var in DNSXInput
	if err := json.Unmarshal(input.Data, &in); err != nil {
		return Output{Artifact: d.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}
	targets := dnsxTargets(input.Target, in)
	if len(targets) == 0 {
		return Output{Artifact: d.Name(), Target: input.Target, Success: false, Error: "target is required"}, nil
	}

	client, err := dnsxlib.New(dnsxOptions(in))
	if err != nil {
		return Output{Artifact: d.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	var results []DNSXResult
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return Output{Artifact: d.Name(), Target: input.Target, Success: false, Error: ctx.Err().Error()}, nil
		default:
		}
		result, err := client.QueryMultiple(target)
		if err != nil {
			results = append(results, DNSXResult{Host: target, Error: err.Error()})
			continue
		}
		results = append(results, dnsxResultFromData(target, result))
	}

	data, _ := json.Marshal(DNSXOutput{Results: results, Total: len(results)})
	return Output{
		Artifact: d.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     data,
	}, nil
}

func (d *DNSXArtifact) Close() error { return nil }

func dnsxTargets(defaultTarget string, input DNSXInput) []string {
	seen := make(map[string]bool)
	var targets []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		targets = append(targets, value)
	}
	add(input.Target)
	for _, target := range input.Targets {
		add(target)
	}
	add(defaultTarget)
	return targets
}

func dnsxOptions(input DNSXInput) dnsxlib.Options {
	options := dnsxlib.DefaultOptions
	if len(input.Resolvers) > 0 {
		options.BaseResolvers = input.Resolvers
	}
	if input.MaxRetries > 0 {
		options.MaxRetries = input.MaxRetries
	}
	options.QueryAll = input.QueryAll
	options.QuestionTypes = dnsxQuestionTypes(input.RecordTypes)
	return options
}

func dnsxQuestionTypes(recordTypes []string) []uint16 {
	if len(recordTypes) == 0 {
		return []uint16{
			miekgdns.TypeA,
			miekgdns.TypeAAAA,
			miekgdns.TypeCNAME,
			miekgdns.TypeNS,
			miekgdns.TypeMX,
			miekgdns.TypeTXT,
		}
	}
	var out []uint16
	seen := make(map[uint16]bool)
	for _, recordType := range recordTypes {
		rt, err := dnsxlib.StringToRequestType(strings.ToLower(strings.TrimSpace(recordType)))
		if err != nil || seen[rt] {
			continue
		}
		seen[rt] = true
		out = append(out, rt)
	}
	if len(out) == 0 {
		return []uint16{miekgdns.TypeA}
	}
	return out
}

func dnsxResultFromData(host string, data *retryabledns.DNSData) DNSXResult {
	if data == nil {
		return DNSXResult{Host: host}
	}
	result := DNSXResult{
		Host:           firstNonEmpty(data.Host, host),
		TTL:            data.TTL,
		Resolver:       data.Resolver,
		A:              data.A,
		AAAA:           data.AAAA,
		CNAME:          data.CNAME,
		MX:             data.MX,
		PTR:            data.PTR,
		SOA:            data.GetSOARecords(),
		NS:             data.NS,
		TXT:            data.TXT,
		SRV:            data.SRV,
		CAA:            data.CAA,
		AllRecords:     data.AllRecords,
		StatusCode:     data.StatusCode,
		StatusCodeRaw:  data.StatusCodeRaw,
		HasInternalIPs: data.HasInternalIPs,
		InternalIPs:    data.InternalIPs,
	}
	if result.Host == "" && net.ParseIP(host) != nil {
		result.Host = host
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
