package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/0xrawptr/weave/internal/data"
)

// CdncheckExtractor extracts resolved IPs and protection/provider findings.
type CdncheckExtractor struct{}

func (c *CdncheckExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type cdncheckOutput struct {
		IsCDN   bool     `json:"is_cdn"`
		IsCloud bool     `json:"is_cloud"`
		IsWAF   bool     `json:"is_waf"`
		CDNName string   `json:"cdn_name"`
		IPs     []string `json:"ips"`
	}
	var out cdncheckOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse cdncheck result: %w", err)
	}

	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)

	anchorType := "domain"
	if net.ParseIP(scanTarget) != nil {
		anchorType = "ip"
	}
	anchorID := data.GenerateID(anchorType, scanTarget, scanTarget)
	addEntity(result, entitySet, Entity{
		ID: anchorID, Type: anchorType, Value: scanTarget,
		Source: "cdncheck", TargetID: targetID, RawData: rawData,
		Confidence: 1.0, Status: "observed",
	})

	for _, ip := range out.IPs {
		if ip == "" {
			continue
		}
		ipID := data.GenerateID("ip", scanTarget, ip)
		addEntity(result, entitySet, Entity{
			ID: ipID, Type: "ip", Value: ip,
			Source: "cdncheck", TargetID: targetID,
			Confidence: 0.8, Status: "observed",
		})
		if anchorType == "domain" {
			addRelation(result, relationSet, Relation{FromID: anchorID, ToID: ipID, Type: RelResolvesTo})
		}
	}

	for _, protectionType := range detectedProtectionTypes(out.IsCDN, out.IsCloud, out.IsWAF) {
		value := out.CDNName
		if value == "" {
			value = protectionType
		}
		protectionID := data.GenerateID("protection", scanTarget, protectionType, value)
		raw, _ := json.Marshal(map[string]string{"type": protectionType, "name": value})
		addEntity(result, entitySet, Entity{
			ID: protectionID, Type: "protection", Value: value,
			Source: "cdncheck", TargetID: targetID, RawData: raw,
			Confidence: 0.9, Status: "observed",
		})
		addRelation(result, relationSet, Relation{FromID: anchorID, ToID: protectionID, Type: RelProtectedBy})
	}
	return result, nil
}

func detectedProtectionTypes(isCDN, isCloud, isWAF bool) []string {
	var values []string
	if isCDN {
		values = append(values, "cdn")
	}
	if isCloud {
		values = append(values, "cloud")
	}
	if isWAF {
		values = append(values, "waf")
	}
	return values
}
