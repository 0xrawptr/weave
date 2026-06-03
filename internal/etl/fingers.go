package etl

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xrawptr/weave/internal/data"
)

type FingersExtractor struct{}

func (f *FingersExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type fingersItem struct {
		Name    string   `json:"name"`
		Product string   `json:"product,omitempty"`
		Version string   `json:"version,omitempty"`
		Tags    []string `json:"tags,omitempty"`
	}
	type fingersOutput struct {
		Frameworks []fingersItem `json:"frameworks"`
		Count      int           `json:"count"`
	}
	var out fingersOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse fingers result: %w", err)
	}
	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	for _, item := range out.Frameworks {
		fpID := data.GenerateID("fingerprint", scanTarget, item.Name)
		result.Entities = append(result.Entities, Entity{
			ID: fpID, Type: "fingerprint", Value: item.Name,
			Source: "fingers", TargetID: targetID, RawData: rawData,
		})
	}
	return result, nil
}
