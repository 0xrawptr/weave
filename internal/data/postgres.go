package data

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
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
		confidence DOUBLE PRECISION DEFAULT 1.0,
		severity TEXT NOT NULL DEFAULT '',
		priority INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'observed',
		source_run_id TEXT NOT NULL DEFAULT '',
		first_seen TIMESTAMPTZ DEFAULT NOW(),
		last_seen TIMESTAMPTZ DEFAULT NOW(),
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

	CREATE TABLE IF NOT EXISTS raw_events (
			id TEXT PRIMARY KEY,
			artifact TEXT NOT NULL,
			target_id TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL DEFAULT '',
			workflow_id TEXT NOT NULL DEFAULT '',
			data JSONB NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

	CREATE TABLE IF NOT EXISTS action_records (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		artifact TEXT NOT NULL,
		input JSONB NOT NULL,
		priority INTEGER NOT NULL DEFAULT 0,
		reason TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'candidate',
		attempts INTEGER NOT NULL DEFAULT 0,
		workflow_id TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		started_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ
	);

	ALTER TABLE assets ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION DEFAULT 1.0;
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'observed';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS source_run_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ DEFAULT NOW();
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW();
	ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT '';

	CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
	CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
	CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
	CREATE INDEX IF NOT EXISTS idx_assets_priority ON assets(priority);
	CREATE INDEX IF NOT EXISTS idx_raw_events_artifact ON raw_events(artifact);
	CREATE INDEX IF NOT EXISTS idx_raw_events_target ON raw_events(target_id);
	CREATE INDEX IF NOT EXISTS idx_action_records_target ON action_records(target);
	CREATE INDEX IF NOT EXISTS idx_action_records_status ON action_records(status);
	CREATE INDEX IF NOT EXISTS idx_action_records_artifact ON action_records(artifact);
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
	if asset.Status == "" {
		asset.Status = "observed"
	}
	if asset.Confidence == 0 {
		asset.Confidence = 1.0
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO assets (id, type, value, source, target_id, raw_data, confidence, severity, priority, status, source_run_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (id) DO UPDATE SET
			raw_data = COALESCE(EXCLUDED.raw_data, assets.raw_data),
			confidence = GREATEST(assets.confidence, EXCLUDED.confidence),
			severity = CASE WHEN EXCLUDED.severity <> '' THEN EXCLUDED.severity ELSE assets.severity END,
			priority = GREATEST(assets.priority, EXCLUDED.priority),
			status = CASE
				WHEN assets.status IN ('false_positive', 'ignored', 'interesting') THEN assets.status
				WHEN EXCLUDED.status <> '' THEN EXCLUDED.status
				ELSE assets.status
			END,
			source_run_id = CASE WHEN EXCLUDED.source_run_id <> '' THEN EXCLUDED.source_run_id ELSE assets.source_run_id END,
			last_seen = NOW()`,
		asset.ID, asset.Type, asset.Value, asset.Source, asset.TargetID, asset.RawData,
		asset.Confidence, asset.Severity, asset.Priority, asset.Status, asset.SourceRunID)
	return err
}

func (p *PostgresStore) InsertRawEvent(ctx context.Context, e *RawEvent) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO raw_events (id, artifact, target_id, target_type, workflow_id, data)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Artifact, e.TargetID, e.TargetType, e.WorkflowID, e.Data)
	return err
}

func (p *PostgresStore) InsertScanResult(ctx context.Context, sr *ScanResult) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO scan_results (id, scan_id, artifact, input, output, success, error, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sr.ID, sr.ScanID, sr.Artifact, sr.Input, sr.Output, sr.Success, sr.Error, sr.DurationMs)
	return err
}

func (p *PostgresStore) ClaimActionRecord(ctx context.Context, record ActionRecord) (bool, error) {
	if record.Status == "" {
		record.Status = "running"
	}
	var id string
	err := p.pool.QueryRow(ctx,
		`INSERT INTO action_records (id, target, artifact, input, priority, reason, status, attempts, workflow_id, started_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, 'running', 1, $7, NOW(), NOW())
		 ON CONFLICT (id) DO UPDATE SET
			target = EXCLUDED.target,
			artifact = EXCLUDED.artifact,
			input = EXCLUDED.input,
			priority = EXCLUDED.priority,
			reason = EXCLUDED.reason,
			status = 'running',
			attempts = action_records.attempts + 1,
			workflow_id = EXCLUDED.workflow_id,
			error = '',
			started_at = NOW(),
			updated_at = NOW()
		 WHERE action_records.status NOT IN ('running', 'completed')
		 RETURNING id`,
		record.ID, record.Target, record.Artifact, record.Input, record.Priority, record.Reason, record.WorkflowID).Scan(&id)
	if err == nil {
		return true, nil
	}
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return false, err
}

func (p *PostgresStore) CompleteActionRecord(ctx context.Context, id, status, errorMessage string) error {
	if status == "" {
		status = "completed"
	}
	_, err := p.pool.Exec(ctx,
		`UPDATE action_records
		 SET status = $2,
			 error = $3,
			 completed_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END,
			 updated_at = NOW()
		 WHERE id = $1`,
		id, status, errorMessage)
	return err
}

func (p *PostgresStore) QueryActionRecords(ctx context.Context, target string) ([]ActionRecord, error) {
	query := `SELECT id, target, artifact, input, priority, reason, status, attempts, workflow_id, error,
		created_at, updated_at, COALESCE(started_at, '0001-01-01'::timestamptz), COALESCE(completed_at, '0001-01-01'::timestamptz)
		FROM action_records WHERE 1=1`
	args := []interface{}{}
	if target != "" {
		query += ` AND target = $1`
		args = append(args, target)
	}
	query += ` ORDER BY priority DESC, updated_at DESC`

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ActionRecord
	for rows.Next() {
		var record ActionRecord
		if err := rows.Scan(&record.ID, &record.Target, &record.Artifact, &record.Input, &record.Priority, &record.Reason, &record.Status, &record.Attempts, &record.WorkflowID, &record.Error, &record.CreatedAt, &record.UpdatedAt, &record.StartedAt, &record.CompletedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (p *PostgresStore) QueryAssets(ctx context.Context, targetID string, assetType string, limit, offset int) ([]Asset, error) {
	query := `SELECT id, type, value, source, target_id, raw_data, confidence, severity, priority, status, source_run_id, first_seen, last_seen, created_at FROM assets WHERE 1=1`
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
		if err := rows.Scan(&a.ID, &a.Type, &a.Value, &a.Source, &a.TargetID, &a.RawData, &a.Confidence, &a.Severity, &a.Priority, &a.Status, &a.SourceRunID, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, nil
}

func (p *PostgresStore) CountAssets(ctx context.Context, targetID, assetType string) (int, error) {
	var count int
	query := `SELECT count(*) FROM assets WHERE 1=1`
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
	}
	if err := p.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (p *PostgresStore) GetAssetByID(ctx context.Context, id string) (*Asset, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, type, value, source, target_id, raw_data, confidence, severity, priority, status, source_run_id, first_seen, last_seen, created_at FROM assets WHERE id = $1 LIMIT 1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("asset %s not found", id)
	}
	var a Asset
	if err := rows.Scan(&a.ID, &a.Type, &a.Value, &a.Source, &a.TargetID, &a.RawData, &a.Confidence, &a.Severity, &a.Priority, &a.Status, &a.SourceRunID, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (p *PostgresStore) Close() {
	p.pool.Close()
}
