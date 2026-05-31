package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Repository struct {
	Postgres *PostgresStore
	Neo4j    *Neo4jStore
	Redis    *RedisStore
}

func NewRepository(pg *PostgresStore, neo *Neo4jStore, rds *RedisStore) *Repository {
	return &Repository{Postgres: pg, Neo4j: neo, Redis: rds}
}

func generateID(parts ...string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%v", parts)))
	return hex.EncodeToString(h[:8])
}

func (r *Repository) SaveAsset(ctx context.Context, asset *Asset) error {
	if err := r.Postgres.InsertAsset(ctx, asset); err != nil {
		return err
	}
	return r.Neo4j.CreateAssetNode(ctx, asset)
}

func (r *Repository) SaveRelation(ctx context.Context, rel AssetRelation) error {
	return r.Neo4j.CreateRelation(ctx, rel)
}

func (r *Repository) CheckDuplicate(ctx context.Context, target, artifact string, input []byte) (bool, error) {
	key := DeduplicationKey(target, artifact, input)
	return r.Redis.IsDuplicate(ctx, key)
}

func (r *Repository) MarkDuplicate(ctx context.Context, target, artifact string, input []byte, ttl time.Duration) error {
	key := DeduplicationKey(target, artifact, input)
	return r.Redis.MarkProcessed(ctx, key, ttl)
}

func (r *Repository) PersistActivityResult(ctx context.Context, artifactName, scanTarget string, data []byte) error {
	switch artifactName {
	case "gogo":
		return r.persistGogoResult(ctx, scanTarget, data)
	case "spray":
		return r.persistSprayResult(ctx, scanTarget, data)
	case "cdncheck":
		return r.persistCdncheckResult(ctx, scanTarget, data)
	default:
		return nil
	}
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
			ID: generateID("ip", item.IP), Type: "ip", Value: item.IP,
			Source: "gogo", TargetID: targetID,
		}
		if err := r.SaveAsset(ctx, ipAsset); err != nil {
			return err
		}

		portID := generateID("port", item.IP, item.Port)
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

		svcID := generateID("service", item.IP, item.Port, item.Protocol)
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
			fpID := generateID("fingerprint", fpName)
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
			ID: generateID("url", item.URL), Type: "url", Value: item.URL,
			Source: "spray", TargetID: targetID,
		}
		if err := r.SaveAsset(ctx, asset); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) Close() {
	if r.Postgres != nil {
		r.Postgres.Close()
	}
	if r.Neo4j != nil {
		r.Neo4j.Close(context.Background())
	}
	if r.Redis != nil {
		r.Redis.Close()
	}
}
