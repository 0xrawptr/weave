package workflow

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// gogoResultItem is the flat structure we unmarshal from gogo's JSON output.
type gogoResultItem struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	URI      string `json:"uri"`
	Protocol string `json:"protocol"`
}

// DomainWorkflowInput is the input for the domain asset discovery workflow.
type DomainWorkflowInput struct {
	Domain string `json:"domain"`
}

// DomainWorkflowResult aggregates results from all stages.
type DomainWorkflowResult struct {
	Domain   string                   `json:"domain"`
	Cdncheck *artifact.ActivityResult `json:"cdncheck,omitempty"`
	Gogo     *artifact.ActivityResult `json:"gogo,omitempty"`
	Spray    *artifact.ActivityResult `json:"spray,omitempty"`
	Fingers  *artifact.ActivityResult `json:"fingers,omitempty"`
	Neutron  *artifact.ActivityResult `json:"neutron,omitempty"`
	Skipped  bool                     `json:"skipped,omitempty"`
	Reason   string                   `json:"reason,omitempty"`
}

// DomainWorkflow orchestrates domain asset discovery.
// Stage 1: gogo port scan → discovers IPs, ports, services
// Stage 2: spray path brute → discovers URLs on web ports
// Stage 3: fingers fingerprint → identifies technologies
// Stage 4: neutron vuln scan → detects vulnerabilities
func DomainWorkflow(ctx workflow.Context, input DomainWorkflowInput) (*DomainWorkflowResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 2,
		},
	})

	result := &DomainWorkflowResult{Domain: input.Domain}

	// Stage 0: CDN / WAF / Cloud detection
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	})
	var cdnResult artifact.ActivityResult
	err := workflow.ExecuteActivity(ctx, "cdncheck", artifact.Input{
		Target: input.Domain,
		Data:   mustMarshal(map[string]interface{}{"target": input.Domain}),
	}).Get(ctx, &cdnResult)
	if err == nil {
		result.Cdncheck = &cdnResult
	}
	if cdnResult.Success && len(cdnResult.Data) > 0 {
		var out struct {
			IsCDN   bool   `json:"is_cdn"`
			IsCloud bool   `json:"is_cloud"`
			IsWAF   bool   `json:"is_waf"`
			CDNName string `json:"cdn_name"`
		}
		if json.Unmarshal(cdnResult.Data, &out) == nil && (out.IsCDN || out.IsWAF) {
			result.Skipped = true
			result.Reason = "domain is behind " + out.CDNName + " CDN/WAF, skipping port scan"
			return result, nil
		}
	}

	// Stage 1: gogo port scan
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	})
	var gogoResult artifact.ActivityResult
	err = workflow.ExecuteActivity(ctx, "gogo", artifact.Input{
		Target: input.Domain,
		Data:   mustMarshal(map[string]interface{}{"ip": input.Domain, "ports": "top1000"}),
	}).Get(ctx, &gogoResult)
	if err != nil {
		return result, err
	}
	result.Gogo = &gogoResult

	// Stage 2 & 3: spray brute + fingers can run in parallel after gogo
	// Use domain name to construct URLs so virtual hosts resolve correctly.
	webURLs := extractDomainURLs(gogoResult, input.Domain)

	if len(webURLs) > 0 {
		// Stage 2: spray path brute
		var sprayResult artifact.ActivityResult
		err = workflow.ExecuteActivity(ctx, "spray", artifact.Input{
			Target: input.Domain,
			Data: mustMarshal(map[string]interface{}{
				"urls": webURLs,
			}),
		}).Get(ctx, &sprayResult)
		if err == nil {
			result.Spray = &sprayResult
		}

		// Stage 3: fingers fingerprint
		var fingersResult artifact.ActivityResult
		err = workflow.ExecuteActivity(ctx, "fingers", artifact.Input{
			Target: input.Domain,
			Data: mustMarshal(map[string]interface{}{
				"mode": "http_match",
				"urls": webURLs,
			}),
		}).Get(ctx, &fingersResult)
		if err == nil {
			result.Fingers = &fingersResult
		}

		// Stage 4: neutron vuln scan on discovered URLs
		for _, url := range webURLs {
			var neutronResult artifact.ActivityResult
			err = workflow.ExecuteActivity(ctx, "neutron", artifact.Input{
				Target: input.Domain,
				Data: mustMarshal(map[string]interface{}{
					"target": url,
				}),
			}).Get(ctx, &neutronResult)
			if err == nil && neutronResult.Success {
				result.Neutron = &neutronResult
			}
		}
	}

	return result, nil
}

func extractWebURLs(gogoResult artifact.ActivityResult) []string {
	// Try GogoSummary first (lightweight, current path).
	var summary struct {
		WebURLs []string `json:"web_urls"`
	}
	if json.Unmarshal(gogoResult.Data, &summary) == nil && len(summary.WebURLs) > 0 {
		return summary.WebURLs
	}
	// Fallback: parse full GogoOutput (legacy or persist data).
	items := parseGogoResults(gogoResult)
	var urls []string
	for _, r := range items {
		urls = append(urls, urlFromItem(r, r.IP))
	}
	return urls
}

// extractDomainURLs is like extractWebURLs but replaces the resolved IP with
// the original domain so that HTTP Host headers carry the correct virtual host.
func extractDomainURLs(gogoResult artifact.ActivityResult, domain string) []string {
	items := parseGogoResults(gogoResult)
	var urls []string
	for _, r := range items {
		urls = append(urls, urlFromItem(r, domain))
	}
	return urls
}

func parseGogoResults(gogoResult artifact.ActivityResult) []gogoResultItem {
	if len(gogoResult.Data) == 0 {
		return nil
	}
	var output struct {
		Results []gogoResultItem `json:"results"`
	}
	if err := json.Unmarshal(gogoResult.Data, &output); err != nil {
		return nil
	}
	return output.Results
}

func urlFromItem(r gogoResultItem, host string) string {
	if r.URI != "" {
		return r.URI
	}
	scheme := "http"
	if strings.HasPrefix(r.Protocol, "https") {
		scheme = "https"
	}
	return scheme + "://" + host + ":" + r.Port
}

func mustMarshal(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}
