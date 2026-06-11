package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ZombieExtractor extracts confirmed credential assets from zombie output.
type ZombieExtractor struct{}

func (z *ZombieExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type zombieItem struct {
		Address  string `json:"address"`
		Service  string `json:"service"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type zombieOutput struct {
		Results []zombieItem `json:"results"`
		Total   int          `json:"total"`
	}
	var out zombieOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse zombie result: %w", err)
	}

	result := &ExtractResult{}
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)
	for _, item := range out.Results {
		if item.Address == "" || item.Username == "" {
			continue
		}
		itemRaw, _ := json.Marshal(item)
		service := strings.TrimSpace(item.Service)
		serviceValue := item.Address
		if service != "" {
			serviceValue = service + "://" + item.Address
		}
		serviceTarget := targetForValue(serviceValue)
		serviceID := assetID("service", serviceValue)
		serviceEntity := Entity{
			ID: serviceID, Type: "service", Value: serviceValue,
			Source: "zombie", RawData: itemRaw,
			Confidence: 0.8, Status: "observed",
		}
		applyTarget(&serviceEntity, serviceTarget)
		addEntity(result, entitySet, serviceEntity)

		credValue := item.Username + ":" + item.Password + "@" + item.Address
		credID := evidenceID("credential", serviceTarget, item.Username, item.Address, service)
		credEntity := Entity{
			ID: credID, Type: "credential", Value: credValue,
			Source: "zombie", RawData: itemRaw,
			Confidence: 1.0, Severity: "high", Priority: 80, Status: "confirmed",
		}
		applyTarget(&credEntity, serviceTarget)
		addEntity(result, entitySet, credEntity)
		addRelation(result, relationSet, Relation{FromID: serviceID, ToID: credID, Type: RelHasCredential})
	}
	return result, nil
}
