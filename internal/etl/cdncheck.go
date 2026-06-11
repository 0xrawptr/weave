package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)

	anchorType := "domain"
	if net.ParseIP(scanTarget) != nil {
		anchorType = "ip"
	}
	anchorTarget := targetForValue(scanTarget)
	anchorID := assetID(anchorType, scanTarget)
	anchorEntity := Entity{
		ID: anchorID, Type: anchorType, Value: scanTarget,
		Source: "cdncheck", RawData: rawData,
		Confidence: 1.0, Status: "observed",
	}
	applyTarget(&anchorEntity, anchorTarget)
	addEntity(result, entitySet, anchorEntity)

	for _, ip := range out.IPs {
		if ip == "" {
			continue
		}
		ipTarget := targetForHost(ip)
		ipID := assetID("ip", ip)
		ipEntity := Entity{
			ID: ipID, Type: "ip", Value: ip,
			Source:     "cdncheck",
			Confidence: 0.8, Status: "observed",
		}
		applyTarget(&ipEntity, ipTarget)
		addEntity(result, entitySet, ipEntity)
		if anchorType == "domain" {
			addRelation(result, relationSet, Relation{FromID: anchorID, ToID: ipID, Type: RelResolvesTo})
		}
	}

	for _, protectionType := range detectedProtectionTypes(out.IsCDN, out.IsCloud, out.IsWAF) {
		value := out.CDNName
		if value == "" {
			value = protectionType
		}
		protectionID := evidenceID("protection", anchorTarget, protectionType, value)
		raw, _ := json.Marshal(map[string]string{"type": protectionType, "name": value})
		protectionEntity := Entity{
			ID: protectionID, Type: "protection", Value: value,
			Source: "cdncheck", RawData: raw,
			Confidence: 0.9, Status: "observed",
		}
		applyTarget(&protectionEntity, anchorTarget)
		addEntity(result, entitySet, protectionEntity)
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
