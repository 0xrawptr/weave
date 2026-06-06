package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

	CREATE TABLE IF NOT EXISTS campaigns (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS campaign_targets (
		id TEXT PRIMARY KEY,
		campaign_id TEXT REFERENCES campaigns(id),
		type TEXT NOT NULL DEFAULT 'unknown',
		value TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		UNIQUE (campaign_id, value)
	);

	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		source TEXT NOT NULL,
		target_id TEXT REFERENCES targets(id),
		raw_data JSONB,
		confidence DOUBLE PRECISION DEFAULT 1.0,
		severity TEXT NOT NULL DEFAULT '',
		priority INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'observed',
		lifecycle_status TEXT NOT NULL DEFAULT 'active',
		raw_hash TEXT NOT NULL DEFAULT '',
		source_run_id TEXT NOT NULL DEFAULT '',
		first_seen TIMESTAMPTZ DEFAULT NOW(),
		last_seen TIMESTAMPTZ DEFAULT NOW(),
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS asset_observations (
		asset_id TEXT REFERENCES assets(id),
		source TEXT NOT NULL,
		raw_data JSONB,
		count INTEGER NOT NULL DEFAULT 1,
		first_seen TIMESTAMPTZ DEFAULT NOW(),
		last_seen TIMESTAMPTZ DEFAULT NOW(),
		PRIMARY KEY (asset_id, source)
	);

	CREATE TABLE IF NOT EXISTS asset_campaigns (
		asset_id TEXT REFERENCES assets(id),
		campaign_id TEXT REFERENCES campaigns(id),
		status TEXT NOT NULL DEFAULT 'active',
		first_seen TIMESTAMPTZ DEFAULT NOW(),
		last_seen TIMESTAMPTZ DEFAULT NOW(),
		PRIMARY KEY (asset_id, campaign_id)
	);

	CREATE TABLE IF NOT EXISTS asset_events (
		id TEXT PRIMARY KEY,
		asset_id TEXT REFERENCES assets(id),
		campaign_id TEXT NOT NULL DEFAULT '',
		event_type TEXT NOT NULL,
		previous_hash TEXT NOT NULL DEFAULT '',
		new_hash TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		target_id TEXT NOT NULL DEFAULT '',
		details JSONB,
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

	CREATE TABLE IF NOT EXISTS artifact_stats (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
		workflow_id TEXT NOT NULL DEFAULT '',
		artifact TEXT NOT NULL,
		target TEXT NOT NULL DEFAULT '',
		engine TEXT NOT NULL DEFAULT '',
		task TEXT NOT NULL DEFAULT '',
		targets BIGINT NOT NULL DEFAULT 0,
		tasks BIGINT NOT NULL DEFAULT 0,
		requests BIGINT NOT NULL DEFAULT 0,
		results BIGINT NOT NULL DEFAULT 0,
		errors BIGINT NOT NULL DEFAULT 0,
		duration_ms BIGINT NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS raw_events (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL DEFAULT '',
			artifact TEXT NOT NULL,
			target_id TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL DEFAULT '',
			workflow_id TEXT NOT NULL DEFAULT '',
			data JSONB NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

	CREATE TABLE IF NOT EXISTS action_records (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
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

	CREATE TABLE IF NOT EXISTS batch_runs (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
		workflow_id TEXT NOT NULL,
		type TEXT NOT NULL,
		target TEXT NOT NULL,
		ports TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'running',
		total_chunks INTEGER NOT NULL DEFAULT 0,
		completed INTEGER NOT NULL DEFAULT 0,
		failed INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS batch_chunks (
		id TEXT PRIMARY KEY,
		batch_id TEXT REFERENCES batch_runs(id),
		target TEXT NOT NULL,
		chunk TEXT NOT NULL,
		workflow_id TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		started_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS work_items (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
		batch_id TEXT NOT NULL DEFAULT '',
		parent_id TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL,
		target TEXT NOT NULL,
		artifact TEXT NOT NULL DEFAULT '',
		queue TEXT NOT NULL DEFAULT '',
		input JSONB,
		priority INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending',
		attempts INTEGER NOT NULL DEFAULT 0,
		max_attempts INTEGER NOT NULL DEFAULT 1,
		workflow_id TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		heartbeat_at TIMESTAMPTZ,
		lease_expires_at TIMESTAMPTZ,
		started_at TIMESTAMPTZ,
		completed_at TIMESTAMPTZ
	);

	ALTER TABLE assets ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION DEFAULT 1.0;
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS campaign_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'observed';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'active';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS raw_hash TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS source_run_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ DEFAULT NOW();
	ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW();
	ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT '';
	ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS campaign_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE action_records ADD COLUMN IF NOT EXISTS campaign_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE batch_runs ADD COLUMN IF NOT EXISTS campaign_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE work_items ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ;
	ALTER TABLE work_items ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
	ALTER TABLE asset_campaigns ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

	CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
	CREATE INDEX IF NOT EXISTS idx_campaign_targets_campaign ON campaign_targets(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_campaign_targets_value ON campaign_targets(value);
	CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
	CREATE INDEX IF NOT EXISTS idx_assets_campaign ON assets(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
	CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
	CREATE INDEX IF NOT EXISTS idx_assets_lifecycle ON assets(lifecycle_status);
	CREATE INDEX IF NOT EXISTS idx_assets_priority ON assets(priority);
	CREATE INDEX IF NOT EXISTS idx_asset_observations_asset ON asset_observations(asset_id);
	CREATE INDEX IF NOT EXISTS idx_asset_observations_source ON asset_observations(source);
	CREATE INDEX IF NOT EXISTS idx_asset_campaigns_campaign ON asset_campaigns(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_asset_campaigns_asset ON asset_campaigns(asset_id);
	CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(asset_id);
	CREATE INDEX IF NOT EXISTS idx_asset_events_campaign ON asset_events(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_raw_events_artifact ON raw_events(artifact);
	CREATE INDEX IF NOT EXISTS idx_raw_events_campaign ON raw_events(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_raw_events_target ON raw_events(target_id);
	CREATE INDEX IF NOT EXISTS idx_artifact_stats_campaign ON artifact_stats(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_artifact_stats_workflow ON artifact_stats(workflow_id);
	CREATE INDEX IF NOT EXISTS idx_artifact_stats_artifact ON artifact_stats(artifact);
	CREATE INDEX IF NOT EXISTS idx_artifact_stats_target ON artifact_stats(target);
	CREATE INDEX IF NOT EXISTS idx_action_records_target ON action_records(target);
	CREATE INDEX IF NOT EXISTS idx_action_records_campaign ON action_records(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_action_records_status ON action_records(status);
	CREATE INDEX IF NOT EXISTS idx_action_records_artifact ON action_records(artifact);
	CREATE INDEX IF NOT EXISTS idx_batch_runs_campaign ON batch_runs(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_batch_runs_status ON batch_runs(status);
	CREATE INDEX IF NOT EXISTS idx_batch_runs_type ON batch_runs(type);
	CREATE INDEX IF NOT EXISTS idx_batch_chunks_batch ON batch_chunks(batch_id);
	CREATE INDEX IF NOT EXISTS idx_batch_chunks_status ON batch_chunks(status);
	CREATE INDEX IF NOT EXISTS idx_work_items_campaign ON work_items(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_work_items_batch ON work_items(batch_id);
	CREATE INDEX IF NOT EXISTS idx_work_items_status ON work_items(status);
	CREATE INDEX IF NOT EXISTS idx_work_items_type ON work_items(type);
	CREATE INDEX IF NOT EXISTS idx_work_items_artifact ON work_items(artifact);
	CREATE INDEX IF NOT EXISTS idx_work_items_queue ON work_items(queue);
	CREATE INDEX IF NOT EXISTS idx_work_items_priority ON work_items(priority);
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

func (p *PostgresStore) UpsertCampaign(ctx context.Context, campaign Campaign) error {
	if campaign.Status == "" {
		campaign.Status = "active"
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO campaigns (id, name, description, status, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			status = EXCLUDED.status,
			updated_at = NOW()`,
		campaign.ID, campaign.Name, campaign.Description, campaign.Status)
	if err != nil {
		return err
	}
	for _, target := range campaign.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if err := p.UpsertCampaignTarget(ctx, CampaignTarget{
			ID:         GenerateID("campaign_target", campaign.ID, target),
			CampaignID: campaign.ID,
			Type:       TargetType(target),
			Value:      target,
			Status:     "active",
		}); err != nil {
			return err
		}
	}
	return nil
}

func (p *PostgresStore) UpsertCampaignTarget(ctx context.Context, target CampaignTarget) error {
	if target.Status == "" {
		target.Status = "active"
	}
	if target.Type == "" {
		target.Type = TargetType(target.Value)
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO campaign_targets (id, campaign_id, type, value, status)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (campaign_id, value) DO UPDATE SET
			type = EXCLUDED.type,
			status = EXCLUDED.status`,
		target.ID, target.CampaignID, target.Type, target.Value, target.Status)
	return err
}

func (p *PostgresStore) GetCampaign(ctx context.Context, id string) (*Campaign, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, description, status, created_at, updated_at FROM campaigns WHERE id = $1`, id)
	var campaign Campaign
	if err := row.Scan(&campaign.ID, &campaign.Name, &campaign.Description, &campaign.Status, &campaign.CreatedAt, &campaign.UpdatedAt); err != nil {
		return nil, err
	}
	targets, err := p.QueryCampaignTargets(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		campaign.Targets = append(campaign.Targets, target.Value)
	}
	return &campaign, nil
}

func (p *PostgresStore) QueryCampaigns(ctx context.Context, status string, limit, offset int) ([]Campaign, error) {
	query := `SELECT id, name, description, status, created_at, updated_at FROM campaigns WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var campaigns []Campaign
	for rows.Next() {
		var campaign Campaign
		if err := rows.Scan(&campaign.ID, &campaign.Name, &campaign.Description, &campaign.Status, &campaign.CreatedAt, &campaign.UpdatedAt); err != nil {
			return nil, err
		}
		campaigns = append(campaigns, campaign)
	}
	return campaigns, rows.Err()
}

func (p *PostgresStore) QueryCampaignTargets(ctx context.Context, campaignID string) ([]CampaignTarget, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, campaign_id, type, value, status, created_at
		FROM campaign_targets WHERE campaign_id = $1 ORDER BY created_at ASC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []CampaignTarget
	for rows.Next() {
		var target CampaignTarget
		if err := rows.Scan(&target.ID, &target.CampaignID, &target.Type, &target.Value, &target.Status, &target.CreatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (p *PostgresStore) UpdateCampaignStatus(ctx context.Context, id, status string) error {
	_, err := p.pool.Exec(ctx, `UPDATE campaigns SET status = $2, updated_at = NOW() WHERE id = $1`, id, status)
	return err
}

func (p *PostgresStore) InsertAsset(ctx context.Context, asset *Asset) error {
	if asset.Status == "" {
		asset.Status = "observed"
	}
	if asset.Lifecycle == "" {
		asset.Lifecycle = "active"
	}
	if asset.Confidence == 0 {
		asset.Confidence = 1.0
	}
	asset.RawHash = rawDataHash(asset.RawData)
	var previousHash string
	err := p.pool.QueryRow(ctx, `SELECT raw_hash FROM assets WHERE id = $1`, asset.ID).Scan(&previousHash)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	existed := err == nil
	_, err = p.pool.Exec(ctx,
		`INSERT INTO assets (id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, priority, status, lifecycle_status, raw_hash, source_run_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (id) DO UPDATE SET
			campaign_id = CASE WHEN EXCLUDED.campaign_id <> '' THEN EXCLUDED.campaign_id ELSE assets.campaign_id END,
			raw_data = COALESCE(EXCLUDED.raw_data, assets.raw_data),
			raw_hash = CASE WHEN EXCLUDED.raw_hash <> '' THEN EXCLUDED.raw_hash ELSE assets.raw_hash END,
			confidence = GREATEST(assets.confidence, EXCLUDED.confidence),
			severity = CASE WHEN EXCLUDED.severity <> '' THEN EXCLUDED.severity ELSE assets.severity END,
			priority = GREATEST(assets.priority, EXCLUDED.priority),
			lifecycle_status = 'active',
			status = CASE
				WHEN assets.status IN ('false_positive', 'ignored', 'interesting', 'confirmed') THEN assets.status
				WHEN EXCLUDED.status = 'noise' AND assets.status <> 'noise' THEN assets.status
				WHEN EXCLUDED.status = 'queued' AND assets.status NOT IN ('queued', 'noise') THEN assets.status
				WHEN assets.status IN ('queued', 'noise') AND EXCLUDED.status NOT IN ('queued', 'noise', '') THEN EXCLUDED.status
				WHEN EXCLUDED.status <> '' THEN EXCLUDED.status
				ELSE assets.status
			END,
			source_run_id = CASE WHEN EXCLUDED.source_run_id <> '' THEN EXCLUDED.source_run_id ELSE assets.source_run_id END,
			last_seen = NOW()`,
		asset.ID, asset.CampaignID, asset.Type, asset.Value, asset.Source, asset.TargetID, asset.RawData,
		asset.Confidence, asset.Severity, asset.Priority, asset.Status, asset.Lifecycle, asset.RawHash, asset.SourceRunID)
	if err != nil {
		return err
	}
	eventType := assetEventType(existed, previousHash, asset.RawHash)
	if err := p.InsertAssetEvent(ctx, AssetEvent{
		ID:           GenerateID("asset_event", asset.ID, asset.CampaignID, eventType, asset.RawHash, fmt.Sprintf("%d", time.Now().UnixNano())),
		AssetID:      asset.ID,
		CampaignID:   asset.CampaignID,
		EventType:    eventType,
		PreviousHash: previousHash,
		NewHash:      asset.RawHash,
		Source:       asset.Source,
		TargetID:     asset.TargetID,
		Details:      assetLifecycleDetails(asset),
	}); err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO asset_observations (asset_id, source, raw_data)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (asset_id, source) DO UPDATE SET
			raw_data = COALESCE(EXCLUDED.raw_data, asset_observations.raw_data),
			count = asset_observations.count + 1,
			last_seen = NOW()`,
		asset.ID, asset.Source, asset.RawData)
	if err != nil {
		return err
	}
	if asset.CampaignID == "" {
		return nil
	}
	if _, err := p.pool.Exec(ctx,
		`INSERT INTO campaigns (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING`,
		asset.CampaignID); err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO asset_campaigns (asset_id, campaign_id, status)
		 VALUES ($1, $2, 'active')
		 ON CONFLICT (asset_id, campaign_id) DO UPDATE SET
			status = 'active',
			last_seen = NOW()`,
		asset.ID, asset.CampaignID)
	return err
}

func (p *PostgresStore) InsertAssetEvent(ctx context.Context, event AssetEvent) error {
	if event.ID == "" {
		event.ID = GenerateID("asset_event", event.AssetID, event.CampaignID, event.EventType, fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO asset_events (id, asset_id, campaign_id, event_type, previous_hash, new_hash, source, target_id, details)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO NOTHING`,
		event.ID, event.AssetID, event.CampaignID, event.EventType, event.PreviousHash, event.NewHash, event.Source, event.TargetID, event.Details)
	return err
}

func (p *PostgresStore) QueryAssetEvents(ctx context.Context, assetID, campaignID, eventType string, limit, offset int) ([]AssetEvent, error) {
	query := `SELECT id, asset_id, campaign_id, event_type, previous_hash, new_hash, source, target_id, details, created_at
		FROM asset_events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if assetID != "" {
		query += fmt.Sprintf(" AND asset_id = $%d", argIdx)
		args = append(args, assetID)
		argIdx++
	}
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if eventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, eventType)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AssetEvent
	for rows.Next() {
		var event AssetEvent
		if err := rows.Scan(&event.ID, &event.AssetID, &event.CampaignID, &event.EventType, &event.PreviousHash, &event.NewHash, &event.Source, &event.TargetID, &event.Details, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (p *PostgresStore) InsertRawEvent(ctx context.Context, e *RawEvent) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO raw_events (id, campaign_id, artifact, target_id, target_type, workflow_id, data)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.CampaignID, e.Artifact, e.TargetID, e.TargetType, e.WorkflowID, e.Data)
	return err
}

func (p *PostgresStore) InsertScanResult(ctx context.Context, sr *ScanResult) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO scan_results (id, scan_id, artifact, input, output, success, error, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sr.ID, sr.ScanID, sr.Artifact, sr.Input, sr.Output, sr.Success, sr.Error, sr.DurationMs)
	return err
}

func (p *PostgresStore) InsertArtifactStat(ctx context.Context, stat ArtifactStat) error {
	if stat.ID == "" {
		stat.ID = GenerateID("artifact_stat", stat.WorkflowID, stat.Artifact, stat.Target, stat.Engine, stat.Task, fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO artifact_stats (id, campaign_id, workflow_id, artifact, target, engine, task, targets, tasks, requests, results, errors, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (id) DO NOTHING`,
		stat.ID, stat.CampaignID, stat.WorkflowID, stat.Artifact, stat.Target, stat.Engine, stat.Task,
		stat.Targets, stat.Tasks, stat.Requests, stat.Results, stat.Errors, stat.DurationMs)
	return err
}

func (p *PostgresStore) QueryArtifactStats(ctx context.Context, campaignID, workflowID, artifactName, target string, limit, offset int) ([]ArtifactStat, error) {
	query := `SELECT id, campaign_id, workflow_id, artifact, target, engine, task, targets, tasks, requests, results, errors, duration_ms, created_at
		FROM artifact_stats WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if workflowID != "" {
		query += fmt.Sprintf(" AND workflow_id = $%d", argIdx)
		args = append(args, workflowID)
		argIdx++
	}
	if artifactName != "" {
		query += fmt.Sprintf(" AND artifact = $%d", argIdx)
		args = append(args, artifactName)
		argIdx++
	}
	if target != "" {
		query += fmt.Sprintf(" AND target = $%d", argIdx)
		args = append(args, target)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []ArtifactStat
	for rows.Next() {
		var stat ArtifactStat
		if err := rows.Scan(&stat.ID, &stat.CampaignID, &stat.WorkflowID, &stat.Artifact, &stat.Target, &stat.Engine, &stat.Task, &stat.Targets, &stat.Tasks, &stat.Requests, &stat.Results, &stat.Errors, &stat.DurationMs, &stat.CreatedAt); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

func (p *PostgresStore) ClaimActionRecord(ctx context.Context, record ActionRecord) (bool, error) {
	if record.Status == "" {
		record.Status = "running"
	}
	var id string
	err := p.pool.QueryRow(ctx,
		`INSERT INTO action_records (id, campaign_id, target, artifact, input, priority, reason, status, attempts, workflow_id, started_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'running', 1, $8, NOW(), NOW())
		 ON CONFLICT (id) DO UPDATE SET
			campaign_id = CASE WHEN EXCLUDED.campaign_id <> '' THEN EXCLUDED.campaign_id ELSE action_records.campaign_id END,
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
		record.ID, record.CampaignID, record.Target, record.Artifact, record.Input, record.Priority, record.Reason, record.WorkflowID).Scan(&id)
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
			 completed_at = CASE WHEN $2 IN ('completed', 'failed', 'skipped') THEN NOW() ELSE completed_at END,
			 updated_at = NOW()
		 WHERE id = $1`,
		id, status, errorMessage)
	return err
}

func (p *PostgresStore) QueryActionRecords(ctx context.Context, target string) ([]ActionRecord, error) {
	return p.QueryActionRecordsFiltered(ctx, target, "")
}

func (p *PostgresStore) QueryActionRecordsFiltered(ctx context.Context, target, campaignID string) ([]ActionRecord, error) {
	query := `SELECT id, campaign_id, target, artifact, input, priority, reason, status, attempts, workflow_id, error,
		created_at, updated_at, COALESCE(started_at, '0001-01-01'::timestamptz), COALESCE(completed_at, '0001-01-01'::timestamptz)
		FROM action_records WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if target != "" {
		query += fmt.Sprintf(" AND target = $%d", argIdx)
		args = append(args, target)
		argIdx++
	}
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
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
		if err := rows.Scan(&record.ID, &record.CampaignID, &record.Target, &record.Artifact, &record.Input, &record.Priority, &record.Reason, &record.Status, &record.Attempts, &record.WorkflowID, &record.Error, &record.CreatedAt, &record.UpdatedAt, &record.StartedAt, &record.CompletedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (p *PostgresStore) UpsertBatchRun(ctx context.Context, run BatchRun) error {
	if run.Status == "" {
		run.Status = "running"
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO batch_runs (id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		 ON CONFLICT (id) DO UPDATE SET
			campaign_id = CASE WHEN EXCLUDED.campaign_id <> '' THEN EXCLUDED.campaign_id ELSE batch_runs.campaign_id END,
			workflow_id = EXCLUDED.workflow_id,
			type = EXCLUDED.type,
			target = EXCLUDED.target,
			ports = EXCLUDED.ports,
			status = EXCLUDED.status,
			total_chunks = EXCLUDED.total_chunks,
			completed = EXCLUDED.completed,
			failed = EXCLUDED.failed,
			updated_at = NOW()`,
		run.ID, run.CampaignID, run.WorkflowID, run.Type, run.Target, run.Ports, run.Status, run.TotalChunks, run.Completed, run.Failed)
	return err
}

func (p *PostgresStore) UpsertBatchChunk(ctx context.Context, chunk BatchChunk) error {
	if chunk.Status == "" {
		chunk.Status = "pending"
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO batch_chunks (id, batch_id, target, chunk, workflow_id, status, error, started_at, completed_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
			CASE WHEN $6 = 'running' THEN NOW() ELSE NULL END,
			CASE WHEN $6 IN ('completed', 'failed') THEN NOW() ELSE NULL END,
			NOW())
		 ON CONFLICT (id) DO UPDATE SET
			workflow_id = CASE WHEN EXCLUDED.workflow_id <> '' THEN EXCLUDED.workflow_id ELSE batch_chunks.workflow_id END,
			status = EXCLUDED.status,
			error = EXCLUDED.error,
			started_at = CASE
				WHEN EXCLUDED.status = 'running' THEN NOW()
				ELSE batch_chunks.started_at
			END,
			completed_at = CASE
				WHEN EXCLUDED.status IN ('completed', 'failed') THEN NOW()
				ELSE batch_chunks.completed_at
			END,
			updated_at = NOW()`,
		chunk.ID, chunk.BatchID, chunk.Target, chunk.Chunk, chunk.WorkflowID, chunk.Status, chunk.Error)
	return err
}

func (p *PostgresStore) QueryBatchRuns(ctx context.Context, status string, limit, offset int) ([]BatchRun, error) {
	return p.QueryBatchRunsFiltered(ctx, status, "", limit, offset)
}

func (p *PostgresStore) QueryBatchRunsFiltered(ctx context.Context, status, campaignID string, limit, offset int) ([]BatchRun, error) {
	query := `SELECT id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, created_at, updated_at
		FROM batch_runs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []BatchRun
	for rows.Next() {
		var run BatchRun
		if err := rows.Scan(&run.ID, &run.CampaignID, &run.WorkflowID, &run.Type, &run.Target, &run.Ports, &run.Status, &run.TotalChunks, &run.Completed, &run.Failed, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (p *PostgresStore) GetBatchRun(ctx context.Context, batchID string) (*BatchRun, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, created_at, updated_at
		FROM batch_runs WHERE id = $1`, batchID)
	var run BatchRun
	if err := row.Scan(&run.ID, &run.CampaignID, &run.WorkflowID, &run.Type, &run.Target, &run.Ports, &run.Status, &run.TotalChunks, &run.Completed, &run.Failed, &run.CreatedAt, &run.UpdatedAt); err != nil {
		return nil, err
	}
	return &run, nil
}

func (p *PostgresStore) QueryBatchChunks(ctx context.Context, batchID, status string, limit, offset int) ([]BatchChunk, error) {
	query := `SELECT id, batch_id, target, chunk, workflow_id, status, error,
		created_at, updated_at, COALESCE(started_at, '0001-01-01'::timestamptz), COALESCE(completed_at, '0001-01-01'::timestamptz)
		FROM batch_chunks WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if batchID != "" {
		query += fmt.Sprintf(" AND batch_id = $%d", argIdx)
		args = append(args, batchID)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY created_at ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []BatchChunk
	for rows.Next() {
		var chunk BatchChunk
		if err := rows.Scan(&chunk.ID, &chunk.BatchID, &chunk.Target, &chunk.Chunk, &chunk.WorkflowID, &chunk.Status, &chunk.Error, &chunk.CreatedAt, &chunk.UpdatedAt, &chunk.StartedAt, &chunk.CompletedAt); err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
	}
	return chunks, rows.Err()
}

func (p *PostgresStore) UpsertWorkItem(ctx context.Context, item WorkItem) error {
	if item.Status == "" {
		item.Status = WorkItemStatusPending
	}
	if !ValidWorkItemStatus(item.Status) {
		return fmt.Errorf("invalid work item status: %s", item.Status)
	}
	if item.MaxAttempts <= 0 {
		item.MaxAttempts = 1
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO work_items (id, campaign_id, batch_id, parent_id, type, target, artifact, queue, input, priority, status, attempts, max_attempts, workflow_id, error, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
		 ON CONFLICT (id) DO UPDATE SET
			campaign_id = CASE WHEN EXCLUDED.campaign_id <> '' THEN EXCLUDED.campaign_id ELSE work_items.campaign_id END,
			batch_id = CASE WHEN EXCLUDED.batch_id <> '' THEN EXCLUDED.batch_id ELSE work_items.batch_id END,
			parent_id = CASE WHEN EXCLUDED.parent_id <> '' THEN EXCLUDED.parent_id ELSE work_items.parent_id END,
			type = EXCLUDED.type,
			target = EXCLUDED.target,
			artifact = EXCLUDED.artifact,
			queue = EXCLUDED.queue,
			input = CASE WHEN EXCLUDED.input IS NOT NULL THEN EXCLUDED.input ELSE work_items.input END,
			priority = EXCLUDED.priority,
			status = CASE
				WHEN work_items.status IN ('running', 'completed') AND EXCLUDED.status = 'pending' THEN work_items.status
				ELSE EXCLUDED.status
			END,
			attempts = CASE WHEN EXCLUDED.attempts > work_items.attempts THEN EXCLUDED.attempts ELSE work_items.attempts END,
			max_attempts = EXCLUDED.max_attempts,
			workflow_id = CASE WHEN EXCLUDED.workflow_id <> '' THEN EXCLUDED.workflow_id ELSE work_items.workflow_id END,
			error = EXCLUDED.error,
			updated_at = NOW()`,
		item.ID, item.CampaignID, item.BatchID, item.ParentID, item.Type, item.Target, item.Artifact, item.Queue, item.Input, item.Priority,
		item.Status, item.Attempts, item.MaxAttempts, item.WorkflowID, item.Error)
	return err
}

func (p *PostgresStore) ClaimWorkItem(ctx context.Context, request WorkItemClaimRequest) (*WorkItem, error) {
	if request.LeaseSeconds <= 0 {
		request.LeaseSeconds = 24 * 60 * 60
	}
	query := `WITH candidate AS (
		SELECT wi.id FROM work_items wi
		WHERE wi.status = 'pending' AND wi.attempts < wi.max_attempts`
	args := []interface{}{}
	argIdx := 1
	if request.CampaignID != "" {
		query += fmt.Sprintf(" AND wi.campaign_id = $%d", argIdx)
		args = append(args, request.CampaignID)
		argIdx++
	}
	if request.BatchID != "" {
		query += fmt.Sprintf(" AND wi.batch_id = $%d", argIdx)
		args = append(args, request.BatchID)
		argIdx++
	}
	if request.Type != "" {
		query += fmt.Sprintf(" AND wi.type = $%d", argIdx)
		args = append(args, request.Type)
		argIdx++
	}
	if request.Artifact != "" {
		query += fmt.Sprintf(" AND wi.artifact = $%d", argIdx)
		args = append(args, request.Artifact)
		argIdx++
	}
	if request.Queue != "" {
		query += fmt.Sprintf(" AND wi.queue = $%d", argIdx)
		args = append(args, request.Queue)
		argIdx++
	}
	if request.Target != "" {
		query += fmt.Sprintf(" AND wi.target = $%d", argIdx)
		args = append(args, request.Target)
		argIdx++
	}
	if request.MaxRunning > 0 {
		query += fmt.Sprintf(" AND (SELECT COUNT(*) FROM work_items r WHERE r.status = 'running' AND r.queue = wi.queue) < $%d", argIdx)
		args = append(args, request.MaxRunning)
		argIdx++
	}
	if request.MaxRunningPerArtifact > 0 {
		query += fmt.Sprintf(" AND (SELECT COUNT(*) FROM work_items r WHERE r.status = 'running' AND r.artifact = wi.artifact) < $%d", argIdx)
		args = append(args, request.MaxRunningPerArtifact)
		argIdx++
	}
	if request.MaxRunningPerCampaign > 0 {
		query += fmt.Sprintf(" AND (SELECT COUNT(*) FROM work_items r WHERE r.status = 'running' AND r.campaign_id = wi.campaign_id) < $%d", argIdx)
		args = append(args, request.MaxRunningPerCampaign)
		argIdx++
	}
	if request.MaxRunningPerTarget > 0 {
		query += fmt.Sprintf(" AND (SELECT COUNT(*) FROM work_items r WHERE r.status = 'running' AND r.target = wi.target) < $%d", argIdx)
		args = append(args, request.MaxRunningPerTarget)
		argIdx++
	}
	query += fmt.Sprintf(` ORDER BY wi.priority DESC, wi.created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	)
	UPDATE work_items SET
		status = 'running',
		attempts = attempts + 1,
		workflow_id = $%d,
		error = '',
		heartbeat_at = NOW(),
		lease_expires_at = NOW() + ($%d * INTERVAL '1 second'),
		started_at = NOW(),
		updated_at = NOW()
	FROM candidate
	WHERE work_items.id = candidate.id
	RETURNING work_items.id, campaign_id, batch_id, parent_id, type, target, artifact, queue, COALESCE(input, '{}'::jsonb), priority, status, attempts, max_attempts, workflow_id, error,
		created_at, updated_at, COALESCE(heartbeat_at, '0001-01-01'::timestamptz), COALESCE(lease_expires_at, '0001-01-01'::timestamptz),
		COALESCE(started_at, '0001-01-01'::timestamptz), COALESCE(completed_at, '0001-01-01'::timestamptz)`, argIdx, argIdx+1)
	args = append(args, request.WorkflowID, request.LeaseSeconds)

	var item WorkItem
	err := p.pool.QueryRow(ctx, query, args...).Scan(&item.ID, &item.CampaignID, &item.BatchID, &item.ParentID, &item.Type, &item.Target, &item.Artifact, &item.Queue, &item.Input, &item.Priority, &item.Status, &item.Attempts, &item.MaxAttempts, &item.WorkflowID, &item.Error, &item.CreatedAt, &item.UpdatedAt, &item.HeartbeatAt, &item.LeaseExpiresAt, &item.StartedAt, &item.CompletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (p *PostgresStore) SetWorkItemStatus(ctx context.Context, id, status, workflowID, errorMessage string, incrementAttempt bool) error {
	if !ValidWorkItemStatus(status) {
		return fmt.Errorf("invalid work item status: %s", status)
	}

	var current string
	var attempts int
	var maxAttempts int
	err := p.pool.QueryRow(ctx, `SELECT status, attempts, max_attempts FROM work_items WHERE id = $1`, id).Scan(&current, &attempts, &maxAttempts)
	if err != nil {
		return err
	}
	if status == WorkItemStatusFailed && attempts >= maxAttempts {
		status = WorkItemStatusDead
		if errorMessage == "" {
			errorMessage = "max attempts reached"
		}
	}
	if !CanTransitionWorkItemStatus(current, status) {
		return fmt.Errorf("invalid work item status transition: %s -> %s", current, status)
	}

	_, err = p.pool.Exec(ctx,
		`UPDATE work_items SET
			status = $2,
			workflow_id = CASE WHEN $3 <> '' THEN $3 ELSE workflow_id END,
			error = $4,
			attempts = attempts + CASE WHEN $5 THEN 1 ELSE 0 END,
			started_at = CASE WHEN $2 = 'running' THEN NOW() ELSE started_at END,
			heartbeat_at = CASE WHEN $2 = 'running' THEN NOW() ELSE heartbeat_at END,
			lease_expires_at = CASE WHEN $2 IN ('completed', 'failed', 'retry_waiting', 'paused', 'cancelled', 'skipped', 'dead') THEN NULL ELSE lease_expires_at END,
			completed_at = CASE WHEN $2 IN ('completed', 'cancelled', 'skipped', 'dead') THEN NOW() ELSE completed_at END,
			updated_at = NOW()
		 WHERE id = $1`,
		id, status, workflowID, errorMessage, incrementAttempt)
	return err
}

func (p *PostgresStore) HeartbeatWorkItem(ctx context.Context, request WorkItemHeartbeatRequest) error {
	if request.ID == "" {
		return fmt.Errorf("work item id is required")
	}
	if request.LeaseSeconds <= 0 {
		request.LeaseSeconds = 24 * 60 * 60
	}
	query := `UPDATE work_items SET
		heartbeat_at = NOW(),
		lease_expires_at = NOW() + ($2 * INTERVAL '1 second'),
		updated_at = NOW()
		WHERE id = $1 AND status = 'running'`
	args := []interface{}{request.ID, request.LeaseSeconds}
	if request.WorkflowID != "" {
		query += ` AND workflow_id = $3`
		args = append(args, request.WorkflowID)
	}
	_, err := p.pool.Exec(ctx, query, args...)
	return err
}

func (p *PostgresStore) QueryWorkItems(ctx context.Context, campaignID, batchID, status, itemType, artifactName, target string, limit, offset int) ([]WorkItem, error) {
	query := `SELECT id, campaign_id, batch_id, parent_id, type, target, artifact, queue, COALESCE(input, '{}'::jsonb), priority, status, attempts, max_attempts, workflow_id, error,
		created_at, updated_at, COALESCE(heartbeat_at, '0001-01-01'::timestamptz), COALESCE(lease_expires_at, '0001-01-01'::timestamptz),
		COALESCE(started_at, '0001-01-01'::timestamptz), COALESCE(completed_at, '0001-01-01'::timestamptz)
		FROM work_items WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if batchID != "" {
		query += fmt.Sprintf(" AND batch_id = $%d", argIdx)
		args = append(args, batchID)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if itemType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, itemType)
		argIdx++
	}
	if artifactName != "" {
		query += fmt.Sprintf(" AND artifact = $%d", argIdx)
		args = append(args, artifactName)
		argIdx++
	}
	if target != "" {
		query += fmt.Sprintf(" AND target = $%d", argIdx)
		args = append(args, target)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY priority DESC, updated_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []WorkItem
	for rows.Next() {
		var item WorkItem
		if err := rows.Scan(&item.ID, &item.CampaignID, &item.BatchID, &item.ParentID, &item.Type, &item.Target, &item.Artifact, &item.Queue, &item.Input, &item.Priority, &item.Status, &item.Attempts, &item.MaxAttempts, &item.WorkflowID, &item.Error, &item.CreatedAt, &item.UpdatedAt, &item.HeartbeatAt, &item.LeaseExpiresAt, &item.StartedAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *PostgresStore) CountWorkItemsByStatus(ctx context.Context, campaignID, batchID, itemType, artifactName string) (map[string]int, error) {
	query := `SELECT status, COUNT(*) FROM work_items WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if campaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if batchID != "" {
		query += fmt.Sprintf(" AND batch_id = $%d", argIdx)
		args = append(args, batchID)
		argIdx++
	}
	if itemType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, itemType)
		argIdx++
	}
	if artifactName != "" {
		query += fmt.Sprintf(" AND artifact = $%d", argIdx)
		args = append(args, artifactName)
	}
	query += ` GROUP BY status`

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts[status] = count
	}
	return counts, rows.Err()
}

func (p *PostgresStore) RetryWorkItems(ctx context.Context, request WorkItemRetryRequest) (WorkItemBulkResult, error) {
	fromStatuses := request.FromStatuses
	if len(fromStatuses) == 0 {
		fromStatuses = []string{WorkItemStatusFailed, WorkItemStatusRetryWaiting}
	}
	for _, status := range fromStatuses {
		if !ValidWorkItemStatus(status) {
			return WorkItemBulkResult{}, fmt.Errorf("invalid work item status: %s", status)
		}
	}

	query := `UPDATE work_items SET
		status = 'pending',
		error = '',
		workflow_id = '',
		attempts = CASE WHEN $1 THEN 0 ELSE attempts END,
		heartbeat_at = NULL,
		lease_expires_at = NULL,
		started_at = NULL,
		completed_at = NULL,
		updated_at = NOW()
		WHERE status = ANY($2)`
	args := []interface{}{request.ResetAttempts, fromStatuses}
	argIdx := 3
	query, args, argIdx = appendWorkItemFilterSQL(query, args, argIdx, request.Filter, false)
	query += ` RETURNING id`

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkItemBulkResult{}, err
	}
	defer rows.Close()

	updated := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return WorkItemBulkResult{}, err
		}
		updated++
	}
	return WorkItemBulkResult{Matched: updated, Updated: updated}, rows.Err()
}

func (p *PostgresStore) ResumeWorkItems(ctx context.Context, filter WorkItemFilter) (WorkItemBulkResult, error) {
	filter.Status = WorkItemStatusPaused
	query := `UPDATE work_items SET
		status = 'pending',
		error = '',
		workflow_id = '',
		heartbeat_at = NULL,
		lease_expires_at = NULL,
		started_at = NULL,
		completed_at = NULL,
		updated_at = NOW()
		WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	query, args, argIdx = appendWorkItemFilterSQL(query, args, argIdx, filter, true)
	query += ` RETURNING id`

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkItemBulkResult{}, err
	}
	defer rows.Close()

	updated := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return WorkItemBulkResult{}, err
		}
		updated++
	}
	return WorkItemBulkResult{Matched: updated, Updated: updated}, rows.Err()
}

func (p *PostgresStore) PauseWorkItems(ctx context.Context, filter WorkItemFilter) (WorkItemBulkResult, error) {
	query := `UPDATE work_items SET
		status = 'paused',
		error = '',
		workflow_id = '',
		heartbeat_at = NULL,
		lease_expires_at = NULL,
		started_at = NULL,
		completed_at = NULL,
		updated_at = NOW()
		WHERE status IN ('pending', 'retry_waiting')`
	args := []interface{}{}
	argIdx := 1
	query, args, argIdx = appendWorkItemFilterSQL(query, args, argIdx, filter, false)
	query += ` RETURNING id`

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkItemBulkResult{}, err
	}
	defer rows.Close()

	updated := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return WorkItemBulkResult{}, err
		}
		updated++
	}
	return WorkItemBulkResult{Matched: updated, Updated: updated}, rows.Err()
}

func (p *PostgresStore) RecoverStaleWorkItems(ctx context.Context, filter WorkItemFilter, limit int) (WorkItemBulkResult, error) {
	if limit <= 0 {
		limit = 1000
	}
	query := `WITH stale AS (
		SELECT id FROM work_items
		WHERE status = 'running'
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at < NOW()`
	args := []interface{}{}
	argIdx := 1
	query, args, argIdx = appendWorkItemFilterSQL(query, args, argIdx, filter, false)
	query += fmt.Sprintf(` ORDER BY lease_expires_at ASC LIMIT $%d
	)
	UPDATE work_items SET
		status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'retry_waiting' END,
		error = CASE WHEN attempts >= max_attempts THEN 'stale running item exceeded max attempts' ELSE 'stale running item recovered' END,
		workflow_id = '',
		heartbeat_at = NULL,
		lease_expires_at = NULL,
		completed_at = CASE WHEN attempts >= max_attempts THEN NOW() ELSE completed_at END,
		updated_at = NOW()
	FROM stale
	WHERE work_items.id = stale.id
	RETURNING work_items.id`, argIdx)
	args = append(args, limit)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkItemBulkResult{}, err
	}
	defer rows.Close()

	updated := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return WorkItemBulkResult{}, err
		}
		updated++
	}
	return WorkItemBulkResult{Matched: updated, Updated: updated}, rows.Err()
}

func (p *PostgresStore) RequeueRetryWaitingWorkItems(ctx context.Context, filter WorkItemFilter, minAgeSeconds, limit int) (WorkItemBulkResult, error) {
	if minAgeSeconds < 0 {
		minAgeSeconds = 0
	}
	if limit <= 0 {
		limit = 1000
	}
	query := `WITH retryable AS (
		SELECT id FROM work_items
		WHERE status = 'retry_waiting'
		  AND attempts < max_attempts`
	args := []interface{}{}
	argIdx := 1
	query, args, argIdx = appendWorkItemFilterSQL(query, args, argIdx, filter, false)
	query += fmt.Sprintf(` AND updated_at <= NOW() - ($%d * INTERVAL '1 second')
		ORDER BY priority DESC, updated_at ASC
		LIMIT $%d
	)
	UPDATE work_items SET
		status = 'pending',
		workflow_id = '',
		error = '',
		heartbeat_at = NULL,
		lease_expires_at = NULL,
		updated_at = NOW()
	FROM retryable
	WHERE work_items.id = retryable.id
	RETURNING work_items.id`, argIdx, argIdx+1)
	args = append(args, minAgeSeconds, limit)

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkItemBulkResult{}, err
	}
	defer rows.Close()

	updated := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return WorkItemBulkResult{}, err
		}
		updated++
	}
	return WorkItemBulkResult{Matched: updated, Updated: updated}, rows.Err()
}

func appendWorkItemFilterSQL(query string, args []interface{}, argIdx int, filter WorkItemFilter, includeStatus bool) (string, []interface{}, int) {
	if filter.ID != "" {
		query += fmt.Sprintf(" AND id = $%d", argIdx)
		args = append(args, filter.ID)
		argIdx++
	}
	if filter.CampaignID != "" {
		query += fmt.Sprintf(" AND campaign_id = $%d", argIdx)
		args = append(args, filter.CampaignID)
		argIdx++
	}
	if filter.BatchID != "" {
		query += fmt.Sprintf(" AND batch_id = $%d", argIdx)
		args = append(args, filter.BatchID)
		argIdx++
	}
	if includeStatus && filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.Type != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, filter.Type)
		argIdx++
	}
	if filter.Artifact != "" {
		query += fmt.Sprintf(" AND artifact = $%d", argIdx)
		args = append(args, filter.Artifact)
		argIdx++
	}
	if filter.Target != "" {
		query += fmt.Sprintf(" AND target = $%d", argIdx)
		args = append(args, filter.Target)
		argIdx++
	}
	return query, args, argIdx
}

func (p *PostgresStore) QueryAssets(ctx context.Context, targetID string, assetType string, limit, offset int) ([]Asset, error) {
	return p.QueryAssetsByStatus(ctx, targetID, assetType, "", limit, offset)
}

func (p *PostgresStore) QueryAssetsByStatus(ctx context.Context, targetID, assetType, status string, limit, offset int) ([]Asset, error) {
	return p.QueryAssetsFiltered(ctx, targetID, assetType, "", status, limit, offset)
}

func (p *PostgresStore) QueryAssetsFiltered(ctx context.Context, targetID, assetType, campaignID, status string, limit, offset int) ([]Asset, error) {
	query := `SELECT id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, priority, status, lifecycle_status, raw_hash, source_run_id, first_seen, last_seen, created_at FROM assets WHERE 1=1`
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
	if campaignID != "" {
		query += fmt.Sprintf(" AND id IN (SELECT asset_id FROM asset_campaigns WHERE campaign_id = $%d)", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
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
		if err := rows.Scan(&a.ID, &a.CampaignID, &a.Type, &a.Value, &a.Source, &a.TargetID, &a.RawData, &a.Confidence, &a.Severity, &a.Priority, &a.Status, &a.Lifecycle, &a.RawHash, &a.SourceRunID, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
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

func (p *PostgresStore) CountAssetsFiltered(ctx context.Context, targetID, assetType, source, status string) (int, error) {
	return p.CountAssetsFilteredByCampaign(ctx, targetID, assetType, source, status, "")
}

func (p *PostgresStore) CountAssetsFilteredByCampaign(ctx context.Context, targetID, assetType, source, status, campaignID string) (int, error) {
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
		argIdx++
	}
	if source != "" {
		query += fmt.Sprintf(" AND source = $%d", argIdx)
		args = append(args, source)
		argIdx++
	}
	if campaignID != "" {
		query += fmt.Sprintf(" AND id IN (SELECT asset_id FROM asset_campaigns WHERE campaign_id = $%d)", argIdx)
		args = append(args, campaignID)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
	}
	if err := p.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (p *PostgresStore) GetAssetByID(ctx context.Context, id string) (*Asset, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, priority, status, lifecycle_status, raw_hash, source_run_id, first_seen, last_seen, created_at FROM assets WHERE id = $1 LIMIT 1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("asset %s not found", id)
	}
	var a Asset
	if err := rows.Scan(&a.ID, &a.CampaignID, &a.Type, &a.Value, &a.Source, &a.TargetID, &a.RawData, &a.Confidence, &a.Severity, &a.Priority, &a.Status, &a.Lifecycle, &a.RawHash, &a.SourceRunID, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (p *PostgresStore) UpdateAssetStatus(ctx context.Context, id, status string) error {
	asset, err := p.GetAssetByID(ctx, id)
	if err != nil {
		return err
	}
	previousStatus := asset.Status
	_, err = p.pool.Exec(ctx,
		`UPDATE assets
		 SET status = $2,
			 last_seen = NOW()
		 WHERE id = $1`,
		id, status)
	if err != nil {
		return err
	}
	if previousStatus == status {
		return nil
	}
	asset.Status = status
	return p.InsertAssetEvent(ctx, AssetEvent{
		ID:           GenerateID("asset_event", id, asset.CampaignID, "status_changed", previousStatus, status, fmt.Sprintf("%d", time.Now().UnixNano())),
		AssetID:      id,
		CampaignID:   asset.CampaignID,
		EventType:    "status_changed",
		PreviousHash: asset.RawHash,
		NewHash:      asset.RawHash,
		Source:       "manual",
		TargetID:     asset.TargetID,
		Details:      assetStatusChangeDetails(asset, previousStatus),
	})
}

func (p *PostgresStore) Close() {
	p.pool.Close()
}

func rawDataHash(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	canonical := raw
	var v interface{}
	if err := json.Unmarshal(raw, &v); err == nil {
		if encoded, err := json.Marshal(v); err == nil {
			canonical = encoded
		}
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:])
}

func assetEventType(existed bool, previousHash, newHash string) string {
	if !existed {
		return "new"
	}
	if previousHash != "" && newHash != "" && previousHash != newHash {
		return "changed"
	}
	return "reproduced"
}

func assetLifecycleDetails(asset *Asset) []byte {
	details := map[string]interface{}{
		"type":             asset.Type,
		"value":            asset.Value,
		"source":           asset.Source,
		"target_id":        asset.TargetID,
		"status":           asset.Status,
		"lifecycle_status": asset.Lifecycle,
		"priority":         asset.Priority,
		"severity":         asset.Severity,
		"confidence":       asset.Confidence,
		"source_run_id":    asset.SourceRunID,
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return nil
	}
	return encoded
}

func assetStatusChangeDetails(asset *Asset, previousStatus string) []byte {
	details := map[string]interface{}{
		"type":             asset.Type,
		"value":            asset.Value,
		"source":           asset.Source,
		"target_id":        asset.TargetID,
		"previous_status":  previousStatus,
		"status":           asset.Status,
		"lifecycle_status": asset.Lifecycle,
		"priority":         asset.Priority,
		"severity":         asset.Severity,
		"confidence":       asset.Confidence,
		"source_run_id":    asset.SourceRunID,
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return nil
	}
	return encoded
}
