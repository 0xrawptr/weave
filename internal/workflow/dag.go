package workflow

import (
	"fmt"
	"sort"
	"time"

	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type DAGWorkflowInput struct {
	Target            string    `json:"target"`
	CampaignID        string    `json:"campaign_id,omitempty"`
	Nodes             []DAGNode `json:"nodes"`
	MaxConcurrency    int       `json:"max_concurrency,omitempty"`
	ContinueOnFailure bool      `json:"continue_on_failure,omitempty"`
}

type DAGNode struct {
	ID         string                    `json:"id"`
	Artifact   string                    `json:"artifact"`
	Target     string                    `json:"target,omitempty"`
	CampaignID string                    `json:"campaign_id,omitempty"`
	Input      map[string]interface{}    `json:"input,omitempty"`
	DependsOn  []string                  `json:"depends_on,omitempty"`
	RunIf      *planner.ConditionRequest `json:"run_if,omitempty"`
	Priority   int                       `json:"priority,omitempty"`
	Reason     string                    `json:"reason,omitempty"`
	Risk       string                    `json:"risk,omitempty"`
	Cost       int                       `json:"cost,omitempty"`
}

type DAGWorkflowResult struct {
	Target    string          `json:"target"`
	Total     int             `json:"total"`
	Completed int             `json:"completed"`
	Failed    int             `json:"failed"`
	Skipped   int             `json:"skipped"`
	Nodes     []DAGNodeResult `json:"nodes,omitempty"`
}

type DAGNodeResult struct {
	ID       string `json:"id"`
	Artifact string `json:"artifact"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type runningDAGNode struct {
	node   DAGNode
	future workflow.Future
}

const (
	dagStatusPending   = "pending"
	dagStatusRunning   = "running"
	dagStatusCompleted = "completed"
	dagStatusFailed    = "failed"
	dagStatusSkipped   = "skipped"
)

// DAGWorkflow executes artifact nodes with dependency ordering and bounded
// concurrency. It is the generic local scheduler for hand-authored or
// planner-generated workflows.
func DAGWorkflow(ctx workflow.Context, input DAGWorkflowInput) (*DAGWorkflowResult, error) {
	if input.MaxConcurrency <= 0 {
		input.MaxConcurrency = 4
	}
	if input.MaxConcurrency > 64 {
		input.MaxConcurrency = 64
	}

	nodes, err := normalizeDAGNodesWithCampaign(input.Target, input.CampaignID, input.Nodes)
	if err != nil {
		return nil, err
	}
	result := &DAGWorkflowResult{Target: input.Target, Total: len(nodes)}
	if len(nodes) == 0 {
		return result, nil
	}

	stateCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	actionCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Hour,
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})

	status := make(map[string]string, len(nodes))
	byID := make(map[string]DAGNode, len(nodes))
	for _, node := range nodes {
		status[node.ID] = dagStatusPending
		byID[node.ID] = node
	}

	remaining := len(nodes)
	for remaining > 0 {
		skipped := markBlockedDAGNodes(status, byID)
		for _, node := range skipped {
			if err := recordSkippedDAGNode(stateCtx, node, "dependency failed or was skipped"); err != nil {
				return result, err
			}
			remaining--
			result.Skipped++
			result.Nodes = append(result.Nodes, DAGNodeResult{
				ID:       node.ID,
				Artifact: node.Artifact,
				Target:   node.Target,
				Status:   dagStatusSkipped,
				Error:    "dependency failed or was skipped",
			})
		}

		ready := readyDAGNodes(status, nodes)
		if len(ready) == 0 {
			if remaining > 0 {
				for _, node := range nodes {
					if status[node.ID] == dagStatusPending {
						if err := recordSkippedDAGNode(stateCtx, node, "dependency cycle or missing dependency"); err != nil {
							return result, err
						}
						status[node.ID] = dagStatusSkipped
						remaining--
						result.Skipped++
						result.Nodes = append(result.Nodes, DAGNodeResult{
							ID:       node.ID,
							Artifact: node.Artifact,
							Target:   node.Target,
							Status:   dagStatusSkipped,
							Error:    "dependency cycle or missing dependency",
						})
					}
				}
			}
			break
		}

		if len(ready) > input.MaxConcurrency {
			ready = ready[:input.MaxConcurrency]
		}

		running := make([]runningDAGNode, 0, len(ready))
		for _, node := range ready {
			status[node.ID] = dagStatusRunning
			conditionOK, conditionMessage, err := evaluateDAGNodeCondition(stateCtx, node)
			if err != nil {
				return result, err
			}
			if !conditionOK {
				if err := recordSkippedDAGNode(stateCtx, node, conditionMessage); err != nil {
					return result, err
				}
				status[node.ID] = dagStatusSkipped
				remaining--
				result.Skipped++
				result.Nodes = append(result.Nodes, DAGNodeResult{
					ID:       node.ID,
					Artifact: node.Artifact,
					Target:   node.Target,
					Status:   dagStatusSkipped,
					Error:    conditionMessage,
				})
				continue
			}

			var claimed bool
			if err := workflow.ExecuteActivity(stateCtx, planner.ClaimActionActivityName, dagNodeAction(ctx, node)).Get(stateCtx, &claimed); err != nil {
				return result, err
			}
			if !claimed {
				status[node.ID] = dagStatusSkipped
				remaining--
				result.Skipped++
				result.Nodes = append(result.Nodes, DAGNodeResult{
					ID:       node.ID,
					Artifact: node.Artifact,
					Target:   node.Target,
					Status:   dagStatusSkipped,
					Error:    "action was already running or completed",
				})
				continue
			}

			future := workflow.ExecuteActivity(actionCtx, node.Artifact, artifact.Input{
				Target:     node.Target,
				CampaignID: node.CampaignID,
				Data:       mustMarshal(node.Input),
			})
			running = append(running, runningDAGNode{node: node, future: future})
		}

		for _, item := range running {
			nodeResult := DAGNodeResult{
				ID:       item.node.ID,
				Artifact: item.node.Artifact,
				Target:   item.node.Target,
			}
			var activityResult artifact.ActivityResult
			err := item.future.Get(actionCtx, &activityResult)
			success := err == nil && activityResult.Success
			if err != nil {
				nodeResult.Error = err.Error()
			} else {
				nodeResult.Error = activityResult.Error
			}
			if completeErr := workflow.ExecuteActivity(stateCtx, planner.CompleteActionActivityName, planner.ActionCompletion{
				ID:      dagNodeActionID(ctx, item.node),
				Success: success,
				Error:   nodeResult.Error,
			}).Get(stateCtx, nil); completeErr != nil {
				return result, completeErr
			}

			remaining--
			if success {
				status[item.node.ID] = dagStatusCompleted
				nodeResult.Status = dagStatusCompleted
				result.Completed++
			} else {
				status[item.node.ID] = dagStatusFailed
				nodeResult.Status = dagStatusFailed
				result.Failed++
			}
			result.Nodes = append(result.Nodes, nodeResult)
		}

		if result.Failed > 0 && !input.ContinueOnFailure {
			for _, node := range nodes {
				if status[node.ID] == dagStatusPending {
					if err := recordSkippedDAGNode(stateCtx, node, "workflow stopped after node failure"); err != nil {
						return result, err
					}
					status[node.ID] = dagStatusSkipped
					remaining--
					result.Skipped++
					result.Nodes = append(result.Nodes, DAGNodeResult{
						ID:       node.ID,
						Artifact: node.Artifact,
						Target:   node.Target,
						Status:   dagStatusSkipped,
						Error:    "workflow stopped after node failure",
					})
				}
			}
		}
	}

	return result, nil
}

func recordSkippedDAGNode(ctx workflow.Context, node DAGNode, reason string) error {
	var claimed bool
	if err := workflow.ExecuteActivity(ctx, planner.ClaimActionActivityName, dagNodeAction(ctx, node)).Get(ctx, &claimed); err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	return workflow.ExecuteActivity(ctx, planner.CompleteActionActivityName, planner.ActionCompletion{
		ID:     dagNodeActionID(ctx, node),
		Status: "skipped",
		Error:  reason,
	}).Get(ctx, nil)
}

func evaluateDAGNodeCondition(ctx workflow.Context, node DAGNode) (bool, string, error) {
	if node.RunIf == nil {
		return true, "", nil
	}
	request := *node.RunIf
	if request.Target == "" {
		request.Target = node.Target
	}
	var conditionResult planner.ConditionResult
	if err := workflow.ExecuteActivity(ctx, planner.EvaluateConditionActivityName, request).Get(ctx, &conditionResult); err != nil {
		return false, "", err
	}
	if conditionResult.OK {
		return true, "", nil
	}
	if conditionResult.Message != "" {
		return false, conditionResult.Message, nil
	}
	return false, "run_if condition was not satisfied", nil
}

func normalizeDAGNodes(defaultTarget string, nodes []DAGNode) ([]DAGNode, error) {
	return normalizeDAGNodesWithCampaign(defaultTarget, "", nodes)
}

func normalizeDAGNodesWithCampaign(defaultTarget, defaultCampaignID string, nodes []DAGNode) ([]DAGNode, error) {
	out := make([]DAGNode, 0, len(nodes))
	seen := make(map[string]bool, len(nodes))
	for i, node := range nodes {
		if node.ID == "" {
			node.ID = fmt.Sprintf("node-%04d", i+1)
		}
		if seen[node.ID] {
			return nil, fmt.Errorf("duplicate dag node id %q", node.ID)
		}
		seen[node.ID] = true
		if node.Artifact == "" {
			return nil, fmt.Errorf("dag node %q artifact is required", node.ID)
		}
		if node.Target == "" {
			node.Target = defaultTarget
		}
		if node.Target == "" {
			return nil, fmt.Errorf("dag node %q target is required", node.ID)
		}
		if node.CampaignID == "" {
			node.CampaignID = defaultCampaignID
		}
		if node.Input == nil {
			node.Input = make(map[string]interface{})
		}
		if node.Priority == 0 {
			node.Priority = 50
		}
		if node.Reason == "" {
			node.Reason = "dag node execution"
		}
		out = append(out, node)
	}
	return out, nil
}

func readyDAGNodes(status map[string]string, nodes []DAGNode) []DAGNode {
	var ready []DAGNode
	for _, node := range nodes {
		if status[node.ID] != dagStatusPending {
			continue
		}
		ok := true
		for _, dep := range node.DependsOn {
			if status[dep] != dagStatusCompleted {
				ok = false
				break
			}
		}
		if ok {
			ready = append(ready, node)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool {
		if ready[i].Priority == ready[j].Priority {
			return ready[i].ID < ready[j].ID
		}
		return ready[i].Priority > ready[j].Priority
	})
	return ready
}

func markBlockedDAGNodes(status map[string]string, byID map[string]DAGNode) []DAGNode {
	var skipped []DAGNode
	changed := true
	for changed {
		changed = false
		for id, node := range byID {
			if status[id] != dagStatusPending {
				continue
			}
			for _, dep := range node.DependsOn {
				depStatus, ok := status[dep]
				if !ok || depStatus == dagStatusFailed || depStatus == dagStatusSkipped {
					status[id] = dagStatusSkipped
					skipped = append(skipped, node)
					changed = true
					break
				}
			}
		}
	}
	sort.SliceStable(skipped, func(i, j int) bool { return skipped[i].ID < skipped[j].ID })
	return skipped
}

func dagNodeAction(ctx workflow.Context, node DAGNode) planner.Action {
	return planner.Action{
		ID:         dagNodeActionID(ctx, node),
		CampaignID: node.CampaignID,
		Target:     node.Target,
		Artifact:   node.Artifact,
		Input:      node.Input,
		Priority:   node.Priority,
		Reason:     node.Reason,
		Status:     "candidate",
		Risk:       node.Risk,
		Cost:       node.Cost,
		DedupKey:   data.GenerateID("dag", node.Target, node.Artifact, string(mustMarshal(node.Input))),
	}
}

func dagNodeActionID(ctx workflow.Context, node DAGNode) string {
	return data.GenerateID("dag", workflow.GetInfo(ctx).WorkflowExecution.ID, node.ID)
}
