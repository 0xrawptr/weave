package workflow

import (
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
)

func nucleiActionMaterializer() actionMaterializer {
	return actionMaterializerFunc{
		materialize: nucleiGroupWorkItemsFromDAGNode,
	}
}

func nucleiGroupWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	baseInput := mapAnyToInterface(node.Input)
	targets := data.ActionInputStrings(baseInput, "targets")
	ids := data.ActionInputStrings(baseInput, "ids")
	tags := data.ActionInputStrings(baseInput, "tags")
	targetChunks := data.ChunkStrings(targets, nucleiGroupTargetSize(input), true)
	if len(targetChunks) == 0 {
		targetChunks = [][]string{nil}
	}
	templateChunks := data.ChunkStrings(ids, nucleiGroupTemplateSize(input), true)
	templateKey := "ids"
	if len(templateChunks) == 0 {
		templateChunks = data.ChunkStrings(tags, nucleiGroupTemplateSize(input), true)
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
