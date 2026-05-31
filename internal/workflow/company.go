package workflow

import (
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// CompanyWorkflowInput is the input for the company asset discovery workflow.
type CompanyWorkflowInput struct {
	Company string   `json:"company"`
	Domains []string `json:"domains,omitempty"` // pre-discovered domains (optional)
}

// CompanyWorkflowResult aggregates results from all company-related scans.
type CompanyWorkflowResult struct {
	Company string                    `json:"company"`
	Domains []DomainWorkflowResult    `json:"domains,omitempty"`
	Spray   *artifact.ActivityResult  `json:"spray,omitempty"`
}

// CompanyWorkflow discovers assets related to a company.
// Stage 1 (optional): company info → discover domains
// Stage 2: For each domain, run DomainWorkflow as a child workflow
func CompanyWorkflow(ctx workflow.Context, input CompanyWorkflowInput) (*CompanyWorkflowResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 2,
		},
	})

	result := &CompanyWorkflowResult{Company: input.Company}

	domains := input.Domains

	// If no pre-discovered domains, try spray to find company-related domains
	if len(domains) == 0 {
		// Search for company-related assets via spray
		var sprayResult artifact.ActivityResult
		err := workflow.ExecuteActivity(ctx, "spray", artifact.Input{
			Target: input.Company,
			Data: mustMarshal(map[string]interface{}{
				"base_urls": []string{input.Company},
				"wordlist":  []string{"admin", "login", "api", "docs", "portal"},
			}),
		}).Get(ctx, &sprayResult)
		if err == nil {
			result.Spray = &sprayResult
		}
		// In a real implementation, you'd use a company info artifact here.
		// For now, just return what we have.
		return result, nil
	}

	// Run DomainWorkflow as a child workflow for each domain
	for _, domain := range domains {
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID: "domain-" + domain,
		})

		var domainResult DomainWorkflowResult
		err := workflow.ExecuteChildWorkflow(childCtx, DomainWorkflow, DomainWorkflowInput{
			Domain: domain,
		}).Get(childCtx, &domainResult)
		if err != nil {
			continue
		}
		result.Domains = append(result.Domains, domainResult)
	}

	return result, nil
}
