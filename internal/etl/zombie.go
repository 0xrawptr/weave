package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
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
	targetID := data.GenerateID("target", scanTarget)
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
		serviceID := data.GenerateID("service", scanTarget, serviceValue)
		addEntity(result, entitySet, Entity{
			ID: serviceID, Type: "service", Value: serviceValue,
			Source: "zombie", TargetID: targetID, RawData: itemRaw,
			Confidence: 0.8, Status: "observed",
		})

		credValue := item.Username + ":" + item.Password + "@" + item.Address
		credID := data.GenerateID("credential", scanTarget, item.Address, service, item.Username, item.Password)
		addEntity(result, entitySet, Entity{
			ID: credID, Type: "credential", Value: credValue,
			Source: "zombie", TargetID: targetID, RawData: itemRaw,
			Confidence: 1.0, Severity: "high", Priority: 80, Status: "confirmed",
		})
		addRelation(result, relationSet, Relation{FromID: serviceID, ToID: credID, Type: RelHasCredential})
	}
	return result, nil
}
