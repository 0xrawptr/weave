package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

type DNSXExtractor struct{}

func (d *DNSXExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}
	type dnsxResult struct {
		Host           string   `json:"host"`
		A              []string `json:"a"`
		AAAA           []string `json:"aaaa"`
		CNAME          []string `json:"cname"`
		MX             []string `json:"mx"`
		PTR            []string `json:"ptr"`
		SOA            []string `json:"soa"`
		NS             []string `json:"ns"`
		TXT            []string `json:"txt"`
		SRV            []string `json:"srv"`
		CAA            []string `json:"caa"`
		HasInternalIPs bool     `json:"has_internal_ips"`
		InternalIPs    []string `json:"internal_ips"`
		Error          string   `json:"error"`
	}
	type dnsxOutput struct {
		Results []dnsxResult `json:"results"`
		Total   int          `json:"total"`
	}
	var out dnsxOutput
	if err := json.Unmarshal(rawData, &out); err != nil {
		return nil, fmt.Errorf("parse dnsx result: %w", err)
	}

	result := &ExtractResult{}
	targetID := data.TargetID(scanTarget)
	entitySet := make(map[string]bool)
	relationSet := make(map[string]bool)

	for _, item := range out.Results {
		host := strings.TrimSpace(item.Host)
		if host == "" {
			host = scanTarget
		}
		if host == "" {
			continue
		}
		anchorType := "domain"
		if net.ParseIP(host) != nil {
			anchorType = "ip"
		}
		anchorID := data.GenerateID(anchorType, scanTarget, host)
		addEntity(result, entitySet, Entity{
			ID: anchorID, Type: anchorType, Value: host,
			Source: "dnsx", TargetID: targetID, RawData: rawData,
			Confidence: 1.0, Status: "observed",
		})

		for _, ip := range append(item.A, item.AAAA...) {
			addDNSXIP(result, entitySet, relationSet, scanTarget, targetID, anchorID, ip, rawData)
		}
		for _, ip := range item.InternalIPs {
			addDNSXIP(result, entitySet, relationSet, scanTarget, targetID, anchorID, ip, rawData)
		}
		for recordType, values := range map[string][]string{
			"cname": item.CNAME,
			"mx":    item.MX,
			"ptr":   item.PTR,
			"soa":   item.SOA,
			"ns":    item.NS,
			"txt":   item.TXT,
			"srv":   item.SRV,
			"caa":   item.CAA,
		} {
			for _, value := range values {
				addDNSXRecord(result, entitySet, relationSet, scanTarget, targetID, anchorID, recordType, value)
			}
		}
	}
	return result, nil
}

func addDNSXIP(result *ExtractResult, entitySet, relationSet map[string]bool, scanTarget, targetID, anchorID, ip string, rawData []byte) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	ipID := data.GenerateID("ip", scanTarget, ip)
	addEntity(result, entitySet, Entity{
		ID: ipID, Type: "ip", Value: ip,
		Source: "dnsx", TargetID: targetID, RawData: rawData,
		Confidence: 0.95, Status: "observed",
	})
	addRelation(result, relationSet, Relation{FromID: anchorID, ToID: ipID, Type: RelResolvesTo})
}

func addDNSXRecord(result *ExtractResult, entitySet, relationSet map[string]bool, scanTarget, targetID, anchorID, recordType, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	recordValue := fmt.Sprintf("%s:%s", recordType, value)
	recordID := data.GenerateID("dns_record", scanTarget, recordValue)
	raw, _ := json.Marshal(map[string]string{"type": recordType, "value": value})
	addEntity(result, entitySet, Entity{
		ID: recordID, Type: "dns_record", Value: recordValue,
		Source: "dnsx", TargetID: targetID, RawData: raw,
		Confidence: 0.9, Status: "observed",
	})
	addRelation(result, relationSet, Relation{FromID: anchorID, ToID: recordID, Type: RelRelatesTo})
}
