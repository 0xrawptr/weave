package etl

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xrawptr/weave/internal/data"
	fingerscommon "github.com/chainreactors/fingers/common"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
)

const gogoSuspiciousTimeoutMillis int64 = 7500

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

// GogoExtractor extracts IP, port, service, and fingerprint entities from gogo output.
type GogoExtractor struct{}

func (g *GogoExtractor) Extract(ctx context.Context, scanTarget string, rawData []byte) (*ExtractResult, error) {
	if rawData == nil {
		return nil, nil
	}

	type gogoOutput struct {
		Results []gogoItem `json:"results"`
	}

	var output gogoOutput
	if err := json.Unmarshal(rawData, &output); err != nil {
		return nil, fmt.Errorf("parse gogo result: %w", err)
	}

	result := &ExtractResult{}
	entitySet := make(map[string]bool)

	for _, item := range output.Results {
		if !isGogoItemAssetCandidate(item) {
			continue
		}
		raw, _ := json.Marshal(item)
		ipTarget := targetForHost(item.IP)

		// IP entity.
		ipID := assetID("ip", item.IP)
		if !entitySet[ipID] {
			entity := Entity{
				ID: ipID, Type: "ip", Value: item.IP,
				Source: "gogo", Confidence: 1.0, Status: "observed",
			}
			applyTarget(&entity, ipTarget)
			result.Entities = append(result.Entities, entity)
			entitySet[ipID] = true
		}

		// Port entity. IP → has_port → port.
		portID := data.GenerateID("port", item.IP, item.Port)
		portEntity := Entity{
			ID: portID, Type: "port", Value: fmt.Sprintf("%s:%s", item.IP, item.Port),
			Source: "gogo", RawData: raw, Confidence: 1.0, Status: "observed",
		}
		applyTarget(&portEntity, ipTarget)
		result.Entities = append(result.Entities, portEntity)
		result.Relations = append(result.Relations, Relation{
			FromID: ipID, ToID: portID, Type: "has_port",
		})

		// Service entity. Port → runs → service.
		serviceValue := fmt.Sprintf("%s://%s:%s", item.Protocol, item.IP, item.Port)
		var serviceQuality *Quality
		serviceStatus := "observed"
		serviceConfidence := 1.0
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
			}
		}
		serviceTarget := targetForURL(serviceValue)
		svcID := assetID("service", serviceTarget.Value)
		serviceEntity := Entity{
			ID: svcID, Type: "service",
			Value:  serviceValue,
			Source: "gogo", RawData: raw, Confidence: serviceConfidence, Status: serviceStatus,
			Quality: serviceQuality,
		}
		applyTarget(&serviceEntity, serviceTarget)
		result.Entities = append(result.Entities, serviceEntity)
		result.Relations = append(result.Relations, Relation{
			FromID: portID, ToID: svcID, Type: "runs",
		})

		// Fingerprint entities. Service → has_fingerprint → fingerprint.
		for fpName, fpRaw := range item.Frameworks {
			framework := parseGogoFramework(fpName, fpRaw)
			fpID := evidenceID("fingerprint", serviceTarget, fpName)
			fpStatus := "observed"
			fpConfidence := 0.7
			if serviceQuality != nil && serviceQuality.Noise {
				fpStatus = "noise"
				fpConfidence = 0.2
			}
			fpEntity := Entity{
				ID: fpID, Type: "fingerprint", Value: fpName,
				Source: "gogo", Confidence: fpConfidence, Status: fpStatus,
				Product: framework.Product, Version: framework.Version,
				Tags: framework.Tags, CPEs: nonEmptyStrings(framework.CPE),
			}
			applyTarget(&fpEntity, serviceTarget)
			result.Entities = append(result.Entities, fpEntity)
			result.Relations = append(result.Relations, Relation{
				FromID: svcID, ToID: fpID, Type: "has_fingerprint",
			})
		}
	}
	return result, nil
}

// IsGogoResultAssetCandidate decides whether a streaming gogo result should be
// promoted from raw evidence into normalized assets and planner follow-ups.
func IsGogoResultAssetCandidate(result *sdktypes.GOGOResult) bool {
	if result == nil {
		return false
	}
	item := gogoItem{
		IP:       result.Ip,
		Port:     result.Port,
		Protocol: result.Protocol,
		Status:   result.Status,
		URI:      result.Uri,
		Host:     result.Host,
		Title:    result.Title,
		Midware:  result.Midware,
		Timing:   result.Timing,
	}
	if !basicGogoItemAssetCandidate(item) {
		return false
	}
	if isGogoHTTPItem(item) {
		return true
	}
	if item.Timing >= gogoSuspiciousTimeoutMillis && !hasNonGuessSDKGogoFramework(result.Frameworks) {
		return false
	}
	return true
}

func isGogoItemAssetCandidate(item gogoItem) bool {
	if !basicGogoItemAssetCandidate(item) {
		return false
	}
	if isGogoHTTPItem(item) {
		return true
	}
	if item.Timing >= gogoSuspiciousTimeoutMillis && !hasNonGuessGogoFramework(item.Frameworks) {
		return false
	}
	return true
}

func basicGogoItemAssetCandidate(item gogoItem) bool {
	if strings.TrimSpace(item.IP) == "" || strings.TrimSpace(item.Port) == "" {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(item.Status))
	switch status {
	case "closed", "close", "filtered", "timeout", "error", "failed", "fail":
		return false
	}
	return true
}

func isGogoHTTPItem(item gogoItem) bool {
	protocol := strings.ToLower(strings.TrimSpace(item.Protocol))
	if strings.HasPrefix(protocol, "http") {
		return true
	}
	if strings.HasPrefix(item.URI, "http://") || strings.HasPrefix(item.URI, "https://") {
		return true
	}
	statusCode, err := strconv.Atoi(strings.TrimSpace(item.Status))
	return err == nil && statusCode >= 100 && statusCode <= 599
}

func hasNonGuessGogoFramework(frameworks map[string]json.RawMessage) bool {
	for _, raw := range frameworks {
		var framework fingerscommon.Framework
		if err := json.Unmarshal(raw, &framework); err != nil {
			return true
		}
		if framework.MatchDetail != nil {
			return true
		}
		for from := range framework.Froms {
			if from != fingerscommon.FrameFromGUESS {
				return true
			}
		}
	}
	return false
}

func hasNonGuessSDKGogoFramework(frameworks fingerscommon.Frameworks) bool {
	for _, framework := range frameworks {
		if framework == nil {
			continue
		}
		if framework.MatchDetail != nil {
			return true
		}
		for from := range framework.Froms {
			if from != fingerscommon.FrameFromGUESS {
				return true
			}
		}
	}
	return false
}

type gogoFrameworkMetadata struct {
	Product string
	Version string
	Tags    []string
	CPE     string
}

func parseGogoFramework(name string, raw json.RawMessage) gogoFrameworkMetadata {
	meta := gogoFrameworkMetadata{Product: name}
	if len(raw) == 0 {
		return meta
	}
	var fw fingerscommon.Framework
	if err := json.Unmarshal(raw, &fw); err != nil {
		return meta
	}
	if fw.Name != "" {
		meta.Product = fw.Name
	}
	meta.Tags = append([]string(nil), fw.Tags...)
	if fw.Attributes != nil {
		if fw.Product != "" {
			meta.Product = fw.Product
		}
		meta.Version = fw.Version
		meta.CPE = fw.CPE()
	}
	return meta
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
