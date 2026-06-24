package workflow

import (
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
)

func nucleiActionMaterializer() actionMaterializer {
	return actionMaterializerFunc{
		validate: func(node planner.DAGPlanNode) bool {
			baseInput := mapAnyToInterface(node.Input)
			return len(stringSliceFromActionInput(baseInput, "targets")) > 0 &&
				(len(stringSliceFromActionInput(baseInput, "ids")) > 0 || len(stringSliceFromActionInput(baseInput, "tags")) > 0)
		},
		materialize: nucleiGroupWorkItemsFromDAGNode,
	}
}

func nucleiGroupWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	baseInput := mapAnyToInterface(node.Input)
	targets := stringSliceFromActionInput(baseInput, "targets")
	ids := stringSliceFromActionInput(baseInput, "ids")
	tags := stringSliceFromActionInput(baseInput, "tags")
	targetChunks := chunkStrings(targets, nucleiGroupTargetSize(input))
	if len(targetChunks) == 0 {
		targetChunks = [][]string{nil}
	}
	templateChunks := chunkStrings(ids, nucleiGroupTemplateSize(input))
	templateKey := "ids"
	if len(templateChunks) == 0 {
		templateChunks = chunkStrings(tags, nucleiGroupTemplateSize(input))
		templateKey = "tags"
	}
	if len(templateChunks) == 0 {
		templateChunks = [][]string{nil}
	}

	var items []data.WorkItem
	shardIndex := 1
	for _, targetChunk := range targetChunks {
		for _, templateChunk := range templateChunks {
			groupInput := copyActionInput(baseInput)
			if len(targetChunk) > 0 {
				groupInput["targets"] = targetChunk
			}
			if len(templateChunk) > 0 {
				groupInput[templateKey] = templateChunk
			}
			groupInput["_shard"] = map[string]interface{}{
				"type":      "nuclei",
				"index":     shardIndex,
				"targets":   len(targetChunk),
				"templates": len(templateChunk),
				"filter":    templateKey,
			}
			items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, groupInput, iteration, maxIterations, shardIndex))
			shardIndex++
		}
	}
	return items
}

func nucleiGroupTargetSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.NucleiGroupTargets > 0 {
		return input.BatchInput.NucleiGroupTargets
	}
	return 25
}

func nucleiGroupTemplateSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.NucleiGroupTemplates > 0 {
		return input.BatchInput.NucleiGroupTemplates
	}
	return 80
}
