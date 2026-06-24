package workflow

import (
	"fmt"

	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
)

type actionMaterializer interface {
	MaterializeWorkItems(SchedulerWorkflowInput, data.WorkItem, planner.DAGPlanNode, int, int) []data.WorkItem
}

type actionMaterializerFunc struct {
	materialize func(SchedulerWorkflowInput, data.WorkItem, planner.DAGPlanNode, int, int) []data.WorkItem
}

func (m actionMaterializerFunc) MaterializeWorkItems(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	return m.materialize(input, parent, node, iteration, maxIterations)
}

var actionMaterializers = map[string]actionMaterializer{
	"spray":  sprayActionMaterializer(),
	"nuclei": nucleiActionMaterializer(),
}

func actionWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	materializer := actionMaterializers[node.Artifact]
	if materializer == nil {
		materializer = actionMaterializerFunc{materialize: singleActionWorkItemFromDAGNode}
	}
	return materializer.MaterializeWorkItems(input, parent, node, iteration, maxIterations)
}

func singleActionWorkItemFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	item := actionWorkItemFromDAGNode(input, parent, node, iteration, maxIterations)
	if item.ID == "" {
		return nil
	}
	return []data.WorkItem{item}
}

func actionWorkItemFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) data.WorkItem {
	itemType := actionWorkItemType(node.Artifact)
	if itemType == "" {
		return data.WorkItem{}
	}
	return actionWorkItemFromDAGNodeInput(input, parent, node, mapAnyToInterface(node.Input), iteration, maxIterations, 0)
}

func actionWorkItemFromDAGNodeInput(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, actionInput map[string]interface{}, iteration, maxIterations, shardIndex int) data.WorkItem {
	itemType := actionWorkItemType(node.Artifact)
	if itemType == "" {
		return data.WorkItem{}
	}
	target := node.Target
	if target == "" {
		target = parent.Target
	}
	idParts := []string{"work_item", input.BatchID, itemType, node.ID}
	if shardIndex > 0 {
		idParts = append(idParts, fmt.Sprintf("shard-%d", shardIndex))
	}
	return data.WorkItem{
		ID:          data.GenerateID(idParts...),
		CampaignID:  input.BatchInput.CampaignID,
		BatchID:     input.BatchID,
		ParentID:    parent.ID,
		Type:        itemType,
		Target:      target,
		Artifact:    node.Artifact,
		Queue:       schedulerQueueForType(itemType),
		Input:       mustMarshal(actionWorkItemInputFromDAGNode(node, target, actionInput, iteration, maxIterations, shardIndex)),
		Schedule:    mergeSchedule(node.Decision.Schedule, parent.Schedule),
		Status:      "pending",
		MaxAttempts: input.BatchInput.MaxAttempts,
	}
}

func actionWorkItemInputFromDAGNode(node planner.DAGPlanNode, target string, actionInput map[string]interface{}, iteration, maxIterations, shardIndex int) data.WorkItemEnvelope {
	return data.WorkItemEnvelope{
		Target:        target,
		ActionInput:   actionInput,
		NodeID:        node.ID,
		Reason:        node.Reason,
		Risk:          node.Risk,
		Cost:          node.Cost,
		DedupKey:      node.DedupKey,
		RunIf:         node.RunIf,
		Iteration:     iteration,
		MaxIterations: maxIterations,
		ShardIndex:    shardIndex,
	}
}

func actionWorkItemType(artifactName string) string {
	def, ok := data.WorkItemDefinitionForArtifact(artifactName)
	if !ok || !def.Action {
		return ""
	}
	return def.Type
}
