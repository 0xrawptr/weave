package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/0xrawptr/weave/internal/data/dbsqlc"
)

type Repository struct {
	Postgres *PostgresStore
	Neo4j    *Neo4jStore
	Redis    *RedisStore
	SQLC     *dbsqlc.Queries
}

func NewRepository(pg *PostgresStore, neo *Neo4jStore, rds *RedisStore) *Repository {
	var sqlc *dbsqlc.Queries
	if pg != nil {
		sqlc = pg.Queries()
	}
	return &Repository{Postgres: pg, Neo4j: neo, Redis: rds, SQLC: sqlc}
}


func (r *Repository) EnsureTarget(ctx context.Context, t *Target) error {
	if r.Postgres == nil {
		return nil
	}
	return r.Postgres.EnsureTarget(ctx, t)
}

func GenerateID(parts ...string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%v", parts)))
	return hex.EncodeToString(h[:8])
}

func TargetID(value string) string {
	return GenerateID("target", value)
}

func (r *Repository) CheckDuplicate(ctx context.Context, target, artifact string, input []byte) (bool, error) {
	key := DeduplicationKey(target, artifact, input)
	return r.Redis.IsDuplicate(ctx, key)
}

func (r *Repository) MarkDuplicate(ctx context.Context, target, artifact string, input []byte, ttl time.Duration) error {
	key := DeduplicationKey(target, artifact, input)
	return r.Redis.MarkProcessed(ctx, key, ttl)
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
