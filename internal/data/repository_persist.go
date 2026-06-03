package data

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) PersistActivityResult(ctx context.Context, artifactName, scanTarget string, data []byte) error {
	// Artifact outputs are persisted through raw_events and ETL pipelines in
	// runtime.processETL. This hook is kept for compatibility with the activity
	// wrapper but should not write normalized assets directly.
	return nil
}

func (r *Repository) persistFingersResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
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
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("parse fingers result: %w", err)
	}

	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "cidr", Value: scanTarget})

	for _, item := range out.Frameworks {
		fpID := generateID("fingerprint", scanTarget, item.Name)
		fpAsset := &Asset{
			ID: fpID, Type: "fingerprint", Value: item.Name,
			Source: "fingers", TargetID: targetID, RawData: data,
		}
		if err := r.SaveAsset(ctx, fpAsset); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) persistNeutronResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
	}
	type neutronItem struct {
		TemplateID string `json:"template_id"`
		Info       string `json:"info"`
		Severity   string `json:"severity"`
		Target     string `json:"target"`
		Matched    string `json:"matched"`
	}
	type neutronOutput struct {
		Results []neutronItem `json:"results"`
		Total   int           `json:"total"`
	}
	var out neutronOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("parse neutron result: %w", err)
	}

	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "cidr", Value: scanTarget})

	for _, item := range out.Results {
		vulnID := generateID("vuln", scanTarget, item.Target, item.TemplateID)
		itemRaw, _ := json.Marshal(item)
		vulnAsset := &Asset{
			ID: vulnID, Type: "vulnerability",
			Value:  fmt.Sprintf("%s: %s", item.Severity, item.Info),
			Source: "neutron", TargetID: targetID, RawData: itemRaw,
		}
		if err := r.SaveAsset(ctx, vulnAsset); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) persistCdncheckResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
	}
	type cdncheckOutput struct {
		IsCDN   bool     `json:"is_cdn"`
		IsCloud bool     `json:"is_cloud"`
		IsWAF   bool     `json:"is_waf"`
		CDNName string   `json:"cdn_name"`
		IPs     []string `json:"ips"`
	}
	var out cdncheckOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("parse cdncheck result: %w", err)
	}

	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "domain", Value: scanTarget})

	if out.IsCDN || out.IsCloud || out.IsWAF {
		asset := &Asset{
			ID:       generateID("protection", scanTarget, out.CDNName),
			Type:     "protection",
			Value:    out.CDNName,
			Source:   "cdncheck",
			TargetID: targetID,
			RawData:  data,
		}
		if err := r.SaveAsset(ctx, asset); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) persistGogoResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
	}

	// Ensure the scan target exists (foreign key requirement)
	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "cidr", Value: scanTarget})

	type gogoItem struct {
		IP         string                     `json:"ip"`
		Port       string                     `json:"port"`
		Protocol   string                     `json:"protocol"`
		Frameworks map[string]json.RawMessage `json:"frameworks,omitempty"`
	}
	type gogoOutput struct {
		Results []gogoItem `json:"results"`
	}

	var output gogoOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return fmt.Errorf("parse gogo result: %w", err)
	}

	for _, item := range output.Results {
		raw, _ := json.Marshal(item)

		ipAsset := &Asset{
			ID: generateID("ip", scanTarget, item.IP), Type: "ip", Value: item.IP,
			Source: "gogo", TargetID: targetID,
		}
		if err := r.SaveAsset(ctx, ipAsset); err != nil {
			return err
		}

		portID := generateID("port", scanTarget, item.IP, item.Port)
		portAsset := &Asset{
			ID: portID, Type: "port", Value: fmt.Sprintf("%s:%s", item.IP, item.Port),
			Source: "gogo", TargetID: targetID, RawData: raw,
		}
		if err := r.SaveAsset(ctx, portAsset); err != nil {
			return err
		}
		if err := r.SaveRelation(ctx, AssetRelation{
			FromAssetID: ipAsset.ID, ToAssetID: portID, Type: "has_port",
		}); err != nil {
			return err
		}

		svcID := generateID("service", scanTarget, item.IP, item.Port, item.Protocol)
		svcAsset := &Asset{
			ID: svcID, Type: "service",
			Value:    fmt.Sprintf("%s://%s:%s", item.Protocol, item.IP, item.Port),
			Source:   "gogo",
			TargetID: targetID,
		}
		if err := r.SaveAsset(ctx, svcAsset); err != nil {
			return err
		}
		if err := r.SaveRelation(ctx, AssetRelation{
			FromAssetID: portID, ToAssetID: svcID, Type: "runs",
		}); err != nil {
			return err
		}

		for fpName := range item.Frameworks {
			fpID := generateID("fingerprint", scanTarget, fpName)
			fpAsset := &Asset{
				ID: fpID, Type: "fingerprint", Value: fpName, Source: "gogo", TargetID: targetID,
			}
			if err := r.SaveAsset(ctx, fpAsset); err != nil {
				return err
			}
			if err := r.SaveRelation(ctx, AssetRelation{
				FromAssetID: svcID, ToAssetID: fpID, Type: "has_fingerprint",
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Repository) persistSprayResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
	}

	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "cidr", Value: scanTarget})

	type sprayItem struct {
		URL        string `json:"url"`
		StatusCode int    `json:"status_code"`
	}
	type sprayOutput struct {
		Results []sprayItem `json:"results"`
	}

	var output sprayOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return fmt.Errorf("parse spray result: %w", err)
	}

	for _, item := range output.Results {
		asset := &Asset{
			ID: generateID("url", scanTarget, item.URL), Type: "url", Value: item.URL,
			Source: "spray", TargetID: targetID,
		}
		if err := r.SaveAsset(ctx, asset); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) persistNucleiResult(ctx context.Context, scanTarget string, data []byte) error {
	if data == nil {
		return nil
	}
	type nucleiItem struct {
		TemplateID string `json:"template_id"`
		Info       string `json:"info"`
		Severity   string `json:"severity"`
		Target     string `json:"target"`
		Matched    string `json:"matched"`
	}
	type nucleiOutput struct {
		Results []nucleiItem `json:"results"`
		Total   int          `json:"total"`
	}
	var out nucleiOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("parse nuclei result: %w", err)
	}

	targetID := generateID("target", scanTarget)
	r.Postgres.EnsureTarget(ctx, &Target{ID: targetID, Type: "cidr", Value: scanTarget})

	for _, item := range out.Results {
		vulnID := generateID("vuln", scanTarget, item.Target, item.TemplateID)
		itemRaw, _ := json.Marshal(item)
		vulnAsset := &Asset{
			ID: vulnID, Type: "vulnerability",
			Value:  fmt.Sprintf("%s: %s", item.Severity, item.Info),
			Source: "nuclei", TargetID: targetID, RawData: itemRaw,
		}
		if err := r.SaveAsset(ctx, vulnAsset); err != nil {
			return err
		}
	}
	return nil
}
