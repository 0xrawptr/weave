package data

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(ctx context.Context, cfg PostgresConfig) (*PostgresStore, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.SSLMode)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("postgres ping: %w", err)
	}

	store := &PostgresStore{pool: pool}
	if err := store.migrate(ctx); err != nil {
		return nil, fmt.Errorf("postgres migrate: %w", err)
	}

	return store, nil
}

func (p *PostgresStore) migrate(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		source TEXT NOT NULL,
		target_id TEXT REFERENCES targets(id),
		raw_data JSONB,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		workflow_id TEXT NOT NULL,
		workflow_type TEXT NOT NULL,
		target_id TEXT REFERENCES targets(id),
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS scan_results (
		id TEXT PRIMARY KEY,
		scan_id TEXT REFERENCES scans(id),
		artifact TEXT NOT NULL,
		input JSONB,
		output JSONB,
		success BOOLEAN DEFAULT false,
		error TEXT,
		duration_ms BIGINT DEFAULT 0,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
	CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
	CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_workflow ON scans(workflow_id);
	`

	_, err := p.pool.Exec(ctx, schema)
	return err
}

func (p *PostgresStore) EnsureTarget(ctx context.Context, t *Target) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO targets (id, type, value) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
		t.ID, t.Type, t.Value)
	return err
}

func (p *PostgresStore) InsertAsset(ctx context.Context, asset *Asset) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO assets (id, type, value, source, target_id, raw_data)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		asset.ID, asset.Type, asset.Value, asset.Source, asset.TargetID, asset.RawData)
	return err
}

func (p *PostgresStore) InsertScanResult(ctx context.Context, sr *ScanResult) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO scan_results (id, scan_id, artifact, input, output, success, error, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sr.ID, sr.ScanID, sr.Artifact, sr.Input, sr.Output, sr.Success, sr.Error, sr.DurationMs)
	return err
}

func (p *PostgresStore) QueryAssets(ctx context.Context, targetID string, assetType string, limit, offset int) ([]Asset, error) {
	query := `SELECT id, type, value, source, target_id, raw_data, created_at FROM assets WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if targetID != "" {
		query += fmt.Sprintf(" AND target_id = $%d", argIdx)
		args = append(args, targetID)
		argIdx++
	}
	if assetType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, assetType)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Type, &a.Value, &a.Source, &a.TargetID, &a.RawData, &a.CreatedAt); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, nil
}

func (p *PostgresStore) Close() {
	p.pool.Close()
}
