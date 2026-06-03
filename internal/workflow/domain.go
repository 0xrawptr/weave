package workflow

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

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
	Neutron  *artifact.ActivityResult `json:"nuclei,omitempty"`
	Skipped  bool                     `json:"skipped,omitempty"`
	Reason   string                   `json:"reason,omitempty"`
}

// DomainWorkflow orchestrates domain asset discovery.
func DomainWorkflow(ctx workflow.Context, input DomainWorkflowInput) (*DomainWorkflowResult, error) {
	result := &DomainWorkflowResult{Domain: input.Domain}

	// Stage 0: CDN / WAF / Cloud detection
	{
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
	}

	skipGogo := false
	if result.Cdncheck != nil && result.Cdncheck.Success && len(result.Cdncheck.Data) > 0 {
		var out struct {
			IsCDN   bool   `json:"is_cdn"`
			IsCloud bool   `json:"is_cloud"`
			IsWAF   bool   `json:"is_waf"`
			CDNName string `json:"cdn_name"`
		}
		if json.Unmarshal(result.Cdncheck.Data, &out) == nil && (out.IsCDN || out.IsWAF) {
			skipGogo = true
			result.Skipped = true
			result.Reason = "domain behind " + out.CDNName + " CDN/WAF, port scan skipped"
		}
	}

	var webURLs []string

	if skipGogo {
		webURLs = []string{"http://" + input.Domain, "https://" + input.Domain}
	} else {
		// Stage 1: gogo port scan
		ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 10 * time.Minute,
			RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
		})
		var gogoResult artifact.ActivityResult
		err := workflow.ExecuteActivity(ctx, "gogo", artifact.Input{
			Target: input.Domain,
			Data:   mustMarshal(map[string]interface{}{"ip": input.Domain, "ports": "top1000"}),
		}).Get(ctx, &gogoResult)
		if err != nil {
			return result, err
		}
		result.Gogo = &gogoResult
		webURLs = extractDomainURLs(gogoResult, input.Domain)
	}

	if len(webURLs) > 0 {
		// Stage 2: spray path brute
		var sprayResult artifact.ActivityResult
		err := workflow.ExecuteActivity(ctx, "spray", artifact.Input{
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

		// Stage 4: nuclei vuln scan
		for _, url := range webURLs {
			var nucleiResult artifact.ActivityResult
			err = workflow.ExecuteActivity(ctx, "nuclei", artifact.Input{
				Target: input.Domain,
				Data: mustMarshal(map[string]interface{}{
					"targets": []string{url},
				}),
			}).Get(ctx, &nucleiResult)
			if err == nil && nucleiResult.Success {
				result.Neutron = &nucleiResult
			}
		}
	}

	return result, nil
}

func extractWebURLs(gogoResult artifact.ActivityResult) []string {
	var summary struct {
		WebURLs []string `json:"web_urls"`
	}
	if json.Unmarshal(gogoResult.Data, &summary) == nil && len(summary.WebURLs) > 0 {
		return summary.WebURLs
	}
	items := parseGogoResults(gogoResult)
	var urls []string
	for _, r := range items {
		urls = append(urls, urlFromItem(r, r.IP))
	}
	return urls
}

func extractDomainURLs(gogoResult artifact.ActivityResult, domain string) []string {
	// Try GogoSummary first.
	var summary struct {
		WebURLs []string `json:"web_urls"`
	}
	if json.Unmarshal(gogoResult.Data, &summary) == nil && len(summary.WebURLs) > 0 {
		var urls []string
		for _, u := range summary.WebURLs {
			// Replace resolved IP with domain for virtual host support.
			// "http://203.0.113.1:80" → "http://example.com:80"
			u2 := domainURL(u, domain)
			if u2 != "" {
				urls = append(urls, u2)
			}
		}
		return urls
	}
	// Fallback: parse full GogoOutput.
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

func domainURL(raw, domain string) string {
	// "http://ip:port" or "https://ip:port" → scheme + domain + port
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return ""
	}
	scheme := raw[:idx]
	rest := raw[idx+3:]
	if _, port, err := net.SplitHostPort(rest); err == nil {
		return scheme + "://" + domain + ":" + port
	}
	return scheme + "://" + domain
}

func mustMarshal(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}
