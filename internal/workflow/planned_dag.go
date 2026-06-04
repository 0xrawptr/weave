package workflow

import (
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type PlannedDAGWorkflowInput struct {
	Target            string `json:"target"`
	CampaignID        string `json:"campaign_id,omitempty"`
	MaxIterations     int    `json:"max_iterations,omitempty"`
	MaxConcurrency    int    `json:"max_concurrency,omitempty"`
	ContinueOnFailure bool   `json:"continue_on_failure,omitempty"`
}

type PlannedDAGWorkflowResult struct {
	Target     string              `json:"target"`
	CampaignID string              `json:"campaign_id,omitempty"`
	Iterations int                 `json:"iterations"`
	Plans      []planner.DAGPlan   `json:"plans,omitempty"`
	Runs       []DAGWorkflowResult `json:"runs,omitempty"`
}

func PlannedDAGWorkflow(ctx workflow.Context, input PlannedDAGWorkflowInput) (*PlannedDAGWorkflowResult, error) {
	if input.MaxIterations <= 0 {
		input.MaxIterations = 5
	}
	if input.MaxConcurrency <= 0 {
		input.MaxConcurrency = 4
	}

	result := &PlannedDAGWorkflowResult{Target: input.Target, CampaignID: input.CampaignID}
	planCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	})

	parentID := workflow.GetInfo(ctx).WorkflowExecution.ID
	for i := 0; i < input.MaxIterations; i++ {
		result.Iterations = i + 1
		var plan planner.DAGPlan
		if err := workflow.ExecuteActivity(planCtx, planner.PlanDAGTargetActivityName, planner.PlanDAGRequest{
			Target:     input.Target,
			CampaignID: input.CampaignID,
		}).Get(planCtx, &plan); err != nil {
			return result, err
		}
		if len(plan.Nodes) == 0 {
			break
		}
		result.Plans = append(result.Plans, plan)

		childID := fmt.Sprintf("%s-dag-%02d", parentID, i+1)
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID: childID,
		})
		var dagResult DAGWorkflowResult
		if err := workflow.ExecuteChildWorkflow(childCtx, DAGWorkflow, dagInputFromPlan(plan, input.MaxConcurrency, input.ContinueOnFailure)).Get(childCtx, &dagResult); err != nil {
			return result, err
		}
		result.Runs = append(result.Runs, dagResult)
		if dagResult.Completed == 0 {
			break
		}
	}

	return result, nil
}

func dagInputFromPlan(plan planner.DAGPlan, maxConcurrency int, continueOnFailure bool) DAGWorkflowInput {
	nodes := make([]DAGNode, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		nodes = append(nodes, DAGNode{
			ID:         node.ID,
			Artifact:   node.Artifact,
			Target:     node.Target,
			CampaignID: node.CampaignID,
			Input:      mapAnyToInterface(node.Input),
			DependsOn:  node.DependsOn,
			RunIf:      node.RunIf,
			Priority:   node.Priority,
			Reason:     node.Reason,
			Risk:       node.Risk,
			Cost:       node.Cost,
		})
	}
	return DAGWorkflowInput{
		Target:            plan.Target,
		CampaignID:        plan.CampaignID,
		Nodes:             nodes,
		MaxConcurrency:    maxConcurrency,
		ContinueOnFailure: continueOnFailure,
	}
}

func mapAnyToInterface(in map[string]any) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
