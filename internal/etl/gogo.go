package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
)

// GogoExtractor extracts IP, port, service, and fingerprint entities from gogo output.
type GogoExtractor struct{}

func (g *GogoExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}

	type gogoItem struct {
		IP         string                     `json:"ip"`
		Port       string                     `json:"port"`
		Protocol   string                     `json:"protocol"`
		Status     string                     `json:"status,omitempty"`
		URI        string                     `json:"uri,omitempty"`
		Host       string                     `json:"host,omitempty"`
		Frameworks map[string]json.RawMessage `json:"frameworks,omitempty"`
		Vulns      map[string]json.RawMessage `json:"vulns,omitempty"`
		Extracteds map[string][]string        `json:"extracted,omitempty"`
		Title      string                     `json:"title,omitempty"`
		Midware    string                     `json:"midware,omitempty"`
		Timing     int64                      `json:"timing,omitempty"`
	}
	type gogoOutput struct {
		Results []gogoItem `json:"results"`
	}

	var output gogoOutput
	if err := json.Unmarshal(rawData, &output); err != nil {
		return nil, fmt.Errorf("parse gogo result: %w", err)
	}

	result := &ExtractResult{}
	targetID := data.GenerateID("target", scanTarget)
	entitySet := make(map[string]bool)

	for _, item := range output.Results {
		raw, _ := json.Marshal(item)

		// IP entity.
		ipID := data.GenerateID("ip", scanTarget, item.IP)
		if !entitySet[ipID] {
			result.Entities = append(result.Entities, Entity{
				ID: ipID, Type: "ip", Value: item.IP,
				Source: "gogo", TargetID: targetID, Confidence: 1.0, Status: "observed",
			})
			entitySet[ipID] = true
		}

		// Port entity. IP → has_port → port.
		portID := data.GenerateID("port", scanTarget, item.IP, item.Port)
		result.Entities = append(result.Entities, Entity{
			ID: portID, Type: "port", Value: fmt.Sprintf("%s:%s", item.IP, item.Port),
			Source: "gogo", TargetID: targetID, RawData: raw, Confidence: 1.0, Status: "observed",
		})
		result.Relations = append(result.Relations, Relation{
			FromID: ipID, ToID: portID, Type: "has_port",
		})

		// Service entity. Port → runs → service.
		serviceValue := fmt.Sprintf("%s://%s:%s", item.Protocol, item.IP, item.Port)
		var serviceQuality *Quality
		serviceStatus := "observed"
		serviceConfidence := 1.0
		servicePriority := 0
		statusCode, _ := strconv.Atoi(item.Status)
		if item.Protocol == "http" || item.Protocol == "https" || item.URI != "" {
			if item.URI != "" {
				if strings.HasPrefix(item.URI, "http://") || strings.HasPrefix(item.URI, "https://") {
					serviceValue = item.URI
				} else {
					serviceValue = strings.TrimRight(serviceValue, "/") + "/" + strings.TrimLeft(item.URI, "/")
				}
			}
			canonical, quality := buildHTTPQuality(HTTPQualityInput{
				URL:        serviceValue,
				StatusCode: statusCode,
				Title:      item.Title,
			})
			if canonical != "" {
				serviceValue = canonical
				serviceQuality = &quality
				serviceStatus = gogoServiceStatus(quality)
				serviceConfidence = httpConfidence(statusCode, quality)
				servicePriority = qualityPriority(0, quality)
			}
		}
		svcID := data.GenerateID("service", scanTarget, item.IP, item.Port, item.Protocol)
		result.Entities = append(result.Entities, Entity{
			ID: svcID, Type: "service",
			Value:  serviceValue,
			Source: "gogo", TargetID: targetID, RawData: raw, Confidence: serviceConfidence, Status: serviceStatus, Priority: servicePriority,
			Quality: serviceQuality,
		})
		result.Relations = append(result.Relations, Relation{
			FromID: portID, ToID: svcID, Type: "runs",
		})

		// Fingerprint entities. Service → has_fingerprint → fingerprint.
		for fpName := range item.Frameworks {
			fpID := data.GenerateID("fingerprint", scanTarget, fpName)
			fpStatus := "observed"
			fpConfidence := 0.7
			if serviceQuality != nil && serviceQuality.Noise {
				fpStatus = "noise"
				fpConfidence = 0.2
			}
			result.Entities = append(result.Entities, Entity{
				ID: fpID, Type: "fingerprint", Value: fpName,
				Source: "gogo", TargetID: targetID, Confidence: fpConfidence, Status: fpStatus,
			})
			result.Relations = append(result.Relations, Relation{
				FromID: svcID, ToID: fpID, Type: "has_fingerprint",
			})
		}
	}
	return result, nil
}

func gogoServiceStatus(quality Quality) string {
	if quality.Noise {
		// A noisy HTTP response on the probed path, such as a root 404, does
		// not make the underlying service noise. Keep the service visible so
		// planner can still run path discovery against the live host:port.
		return "observed"
	}
	switch quality.Layer {
	case "critical", "interesting":
		return "candidate"
	default:
		return "observed"
	}
}
