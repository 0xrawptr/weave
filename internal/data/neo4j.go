package data

import (
	"context"
	"fmt"
	"regexp"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jConfig struct {
	URI      string
	User     string
	Password string
}

type Neo4jStore struct {
	driver neo4j.DriverWithContext
}

func NewNeo4jStore(ctx context.Context, cfg Neo4jConfig) (*Neo4jStore, error) {
	driver, err := neo4j.NewDriverWithContext(cfg.URI, neo4j.BasicAuth(cfg.User, cfg.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("neo4j connect: %w", err)
	}

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("neo4j verify: %w", err)
	}

	store := &Neo4jStore{driver: driver}
	if err := store.initConstraints(ctx); err != nil {
		return nil, fmt.Errorf("neo4j init: %w", err)
	}

	return store, nil
}

func (n *Neo4jStore) initConstraints(ctx context.Context) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE`,
		nil)
	return err
}

// CreateAssetNode creates an Asset node in the graph.
func (n *Neo4jStore) CreateAssetNode(ctx context.Context, asset *Asset) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MERGE (a:Asset {id: $id})
		 SET a.type = $type,
			 a.value = $value,
			 a.source = $source,
			 a.target_id = $targetID,
			 a.campaign_id = CASE WHEN $campaignID <> '' THEN $campaignID ELSE coalesce(a.campaign_id, '') END,
			 a.campaign_ids = CASE
				WHEN $campaignID = '' THEN coalesce(a.campaign_ids, [])
				WHEN $campaignID IN coalesce(a.campaign_ids, []) THEN coalesce(a.campaign_ids, [])
				ELSE coalesce(a.campaign_ids, []) + [$campaignID]
			 END,
			 a.confidence = $confidence,
			 a.severity = $severity,
			 a.status = $status`,
		map[string]interface{}{
			"id":         asset.ID,
			"type":       asset.Type,
			"value":      asset.Value,
			"source":     asset.Source,
			"targetID":   asset.TargetID,
			"campaignID": asset.CampaignID,
			"confidence": asset.Confidence,
			"severity":   asset.Severity,
			"status":     asset.Status,
		})
	return err
}

// CreateRelation creates a relationship between two asset nodes.
func (n *Neo4jStore) CreateRelation(ctx context.Context, rel AssetRelation) error {
	if !validRelationType(rel.Type) {
		return fmt.Errorf("invalid relation type %q", rel.Type)
	}
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	query := fmt.Sprintf(
		`MATCH (a:Asset {id: $fromID}), (b:Asset {id: $toID})
		 MERGE (a)-[r:%s]->(b)`, rel.Type)

	_, err := session.Run(ctx, query, map[string]interface{}{
		"fromID": rel.FromAssetID,
		"toID":   rel.ToAssetID,
	})
	return err
}

func (n *Neo4jStore) UpdateAssetStatus(ctx context.Context, id, status string) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MATCH (a:Asset {id: $id})
		 SET a.status = $status`,
		map[string]interface{}{"id": id, "status": status})
	return err
}

var relationTypePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validRelationType(relType string) bool {
	if relType == "" {
		return false
	}
	return relationTypePattern.MatchString(relType)
}

// QueryGraph traverses related assets starting from a given asset ID.
func (n *Neo4jStore) QueryGraph(ctx context.Context, assetID string, depth int) ([]map[string]interface{}, error) {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := fmt.Sprintf(
		`MATCH (a:Asset {id: $id})-[*1..%d]-(related)
		 RETURN DISTINCT related.id AS id, related.type AS type, related.value AS value, related.source AS source`,
		depth)

	result, err := session.Run(ctx, query, map[string]interface{}{"id": assetID})
	if err != nil {
		return nil, err
	}

	var nodes []map[string]interface{}
	for result.Next(ctx) {
		record := result.Record()
		nodes = append(nodes, record.AsMap())
	}
	return nodes, result.Err()
}

// QueryKnowledgeEvidence returns normalized knowledge nodes connected to a target.
func (n *Neo4jStore) QueryKnowledgeEvidence(ctx context.Context, targetID, campaignID string) ([]EvidenceRecord, error) {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (seed:Asset {target_id: $targetID})
		 WHERE seed.type IN ['fingerprint', 'product', 'cve']
		   AND ($campaignID = '' OR seed.campaign_id = $campaignID OR $campaignID IN coalesce(seed.campaign_ids, []))
		 MATCH p = shortestPath((seed)-[*0..4]-(n:Asset {target_id: $targetID}))
		 WHERE n.type IN ['fingerprint', 'product', 'cve', 'template', 'intel', 'cpe', 'cwe']
		   AND ($campaignID = '' OR n.campaign_id = $campaignID OR $campaignID IN coalesce(n.campaign_ids, []))
		 RETURN DISTINCT n.type AS type,
			 n.value AS value,
			 n.source AS source,
			 n.confidence AS confidence,
			 n.severity AS severity,
			 n.status AS status,
			 [node IN nodes(p) | {type: node.type, value: node.value}] AS path_nodes,
			 [rel IN relationships(p) | type(rel)] AS path_rels`,
		map[string]interface{}{"targetID": targetID, "campaignID": campaignID})
	if err != nil {
		return nil, err
	}

	var evidence []EvidenceRecord
	for result.Next(ctx) {
		record := result.Record().AsMap()
		evidence = append(evidence, EvidenceRecord{
			Type:       stringField(record["type"]),
			Value:      stringField(record["value"]),
			Source:     stringField(record["source"]),
			Confidence: floatField(record["confidence"]),
			Severity:   stringField(record["severity"]),
			Status:     stringField(record["status"]),
			Path:       evidencePath(record["path_nodes"], record["path_rels"]),
		})
	}
	return evidence, result.Err()
}

func (n *Neo4jStore) Close(ctx context.Context) {
	n.driver.Close(ctx)
}

func stringField(value interface{}) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func floatField(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0
	}
}

func evidencePath(rawNodes, rawRels interface{}) []EvidencePathStep {
	nodes, ok := rawNodes.([]interface{})
	if !ok || len(nodes) == 0 {
		return nil
	}
	rels, _ := rawRels.([]interface{})
	steps := make([]EvidencePathStep, 0, len(nodes))
	for i, rawNode := range nodes {
		node, ok := rawNode.(map[string]interface{})
		if !ok {
			continue
		}
		step := EvidencePathStep{
			Type:  stringField(node["type"]),
			Value: stringField(node["value"]),
		}
		if i > 0 && i-1 < len(rels) {
			step.Relation = stringField(rels[i-1])
		}
		if step.Type != "" && step.Value != "" {
			steps = append(steps, step)
		}
	}
	return steps
}
