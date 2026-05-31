package data

import (
	"context"
	"fmt"

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
		 SET a.type = $type, a.value = $value, a.source = $source, a.target_id = $targetID`,
		map[string]interface{}{
			"id":        asset.ID,
			"type":      asset.Type,
			"value":     asset.Value,
			"source":    asset.Source,
			"targetID":  asset.TargetID,
		})
	return err
}

// CreateRelation creates a relationship between two asset nodes.
func (n *Neo4jStore) CreateRelation(ctx context.Context, rel AssetRelation) error {
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

func (n *Neo4jStore) Close(ctx context.Context) {
	n.driver.Close(ctx)
}
