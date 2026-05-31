package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(cfg RedisConfig) *RedisStore {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return &RedisStore{client: client}
}

func (r *RedisStore) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// DeduplicationKey generates a cache key for a target+artifact combination.
func DeduplicationKey(target, artifact string, input []byte) string {
	hash := sha256.Sum256(input)
	return fmt.Sprintf("dedup:%s:%s:%s", target, artifact, hex.EncodeToString(hash[:8]))
}

// IsDuplicate checks if this target+artifact+input combination was already processed.
func (r *RedisStore) IsDuplicate(ctx context.Context, key string) (bool, error) {
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// MarkProcessed marks a target+artifact+input as processed with a TTL.
func (r *RedisStore) MarkProcessed(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Set(ctx, key, "1", ttl).Err()
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}
