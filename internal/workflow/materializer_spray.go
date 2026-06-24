package workflow

import (
	"github.com/0xrawptr/weave/internal/artifact"
	"github.com/0xrawptr/weave/internal/data"
	"github.com/0xrawptr/weave/internal/planner"
)

type wordlistRange struct {
	Offset int
	Limit  int
}

func sprayActionMaterializer() actionMaterializer {
	return actionMaterializerFunc{
		validate: func(node planner.DAGPlanNode) bool {
			baseInput := mapAnyToInterface(node.Input)
			return len(stringSliceFromActionInput(baseInput, "base_urls")) > 0 || len(stringSliceFromActionInput(baseInput, "urls")) > 0
		},
		materialize: sprayShardWorkItemsFromDAGNode,
	}
}

func sprayShardWorkItemsFromDAGNode(input SchedulerWorkflowInput, parent data.WorkItem, node planner.DAGPlanNode, iteration, maxIterations int) []data.WorkItem {
	baseInput := mapAnyToInterface(node.Input)
	baseURLs := stringSliceFromActionInput(baseInput, "base_urls")
	checkURLs := stringSliceFromActionInput(baseInput, "urls")
	wordlist := stringSliceFromActionInput(baseInput, "wordlist")
	fullWordlistMode := len(wordlist) == 0 && stringFromActionInput(baseInput, "wordlist_mode") == "full"
	var wordRanges []wordlistRange
	if fullWordlistMode {
		wordRanges = chunkWordlistRanges(len(artifact.FullSprayWordlist()), sprayShardWordSize(input))
		if len(wordRanges) == 0 {
			wordRanges = []wordlistRange{{Offset: 0, Limit: 0}}
		}
	}

	baseURLChunkSize := sprayShardBaseURLSize(input)
	if fullWordlistMode {
		baseURLChunkSize = 1
	}
	baseURLChunks := chunkStrings(baseURLs, baseURLChunkSize)
	if len(baseURLChunks) == 0 {
		baseURLChunks = [][]string{nil}
	}
	checkURLChunks := chunkStrings(checkURLs, sprayShardBaseURLSize(input))
	if len(checkURLChunks) == 0 {
		checkURLChunks = [][]string{nil}
	}
	wordChunks := chunkStrings(wordlist, sprayShardWordSize(input))
	if len(wordChunks) == 0 && !fullWordlistMode {
		wordChunks = [][]string{nil}
	}

	var items []data.WorkItem
	shardIndex := 1
	if len(baseURLs) > 0 {
		if fullWordlistMode {
			for _, urlChunk := range baseURLChunks {
				for _, wordRange := range wordRanges {
					shardInput := copyActionInput(baseInput)
					shardInput["base_urls"] = urlChunk
					shardInput["wordlist_mode"] = "full"
					shardInput["wordlist_offset"] = wordRange.Offset
					shardInput["wordlist_limit"] = wordRange.Limit
					delete(shardInput, "wordlist")
					shardInput["_shard"] = map[string]interface{}{
						"type":            "spray",
						"index":           shardIndex,
						"base_urls":       len(urlChunk),
						"word_count":      wordRange.Limit,
						"wordlist_mode":   "full",
						"wordlist_offset": wordRange.Offset,
					}
					items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, shardInput, iteration, maxIterations, shardIndex))
					shardIndex++
				}
			}
			return items
		}
		for _, urlChunk := range baseURLChunks {
			for _, wordChunk := range wordChunks {
				shardInput := copyActionInput(baseInput)
				shardInput["base_urls"] = urlChunk
				if len(wordChunk) > 0 {
					shardInput["wordlist"] = wordChunk
				}
				shardInput["_shard"] = map[string]interface{}{
					"type":       "spray",
					"index":      shardIndex,
					"base_urls":  len(urlChunk),
					"word_count": len(wordChunk),
				}
				items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, shardInput, iteration, maxIterations, shardIndex))
				shardIndex++
			}
		}
		return items
	}
	if len(checkURLs) > 0 {
		for _, urlChunk := range checkURLChunks {
			shardInput := copyActionInput(baseInput)
			shardInput["urls"] = urlChunk
			shardInput["_shard"] = map[string]interface{}{"type": "spray_check", "index": shardIndex, "urls": len(urlChunk)}
			items = append(items, actionWorkItemFromDAGNodeInput(input, parent, node, shardInput, iteration, maxIterations, shardIndex))
			shardIndex++
		}
		return items
	}
	return nil
}

func chunkWordlistRanges(total, size int) []wordlistRange {
	if total <= 0 {
		return nil
	}
	if size <= 0 {
		size = total
	}
	ranges := make([]wordlistRange, 0, (total+size-1)/size)
	for offset := 0; offset < total; offset += size {
		limit := size
		if offset+limit > total {
			limit = total - offset
		}
		ranges = append(ranges, wordlistRange{Offset: offset, Limit: limit})
	}
	return ranges
}

func sprayShardBaseURLSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.SprayShardBaseURLs > 0 {
		return input.BatchInput.SprayShardBaseURLs
	}
	return 1
}

func sprayShardWordSize(input SchedulerWorkflowInput) int {
	if input.BatchInput.SprayShardWords > 0 {
		return input.BatchInput.SprayShardWords
	}
	return 2000
}
