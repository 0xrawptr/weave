-- Full schema for sqlc code generation
CREATE TABLE campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    phase TEXT NOT NULL DEFAULT 'bootstrap',
    phase_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE campaign_phase_events (
    id TEXT PRIMARY KEY,
    campaign_id TEXT REFERENCES campaigns(id),
    batch_id TEXT NOT NULL DEFAULT '',
    from_phase TEXT NOT NULL DEFAULT '',
    to_phase TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE campaign_targets (
    id TEXT PRIMARY KEY,
    campaign_id TEXT REFERENCES campaigns(id),
    type TEXT NOT NULL DEFAULT 'unknown',
    value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (campaign_id, value)
);

CREATE TABLE batch_runs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    workflow_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    total_chunks INTEGER NOT NULL DEFAULT 0,
    completed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE batch_chunks (
    id TEXT PRIMARY KEY,
    batch_id TEXT REFERENCES batch_runs(id),
    target TEXT NOT NULL,
    chunk TEXT NOT NULL,
    workflow_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE work_items (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL DEFAULT '',
    batch_id TEXT NOT NULL DEFAULT '',
    parent_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    artifact TEXT NOT NULL DEFAULT '',
    queue TEXT NOT NULL DEFAULT '',
    input JSONB NOT NULL DEFAULT '{}',
    schedule TEXT NOT NULL DEFAULT 'batch',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    workflow_id TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    heartbeat_stale_at TIMESTAMPTZ,
    tail BOOLEAN NOT NULL DEFAULT false,
    tail_at TIMESTAMPTZ,
    tail_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    raw_data JSONB,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    severity TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'observed',
    lifecycle TEXT NOT NULL DEFAULT 'active',
    raw_hash TEXT NOT NULL DEFAULT '',
    source_run_id TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE raw_events (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL DEFAULT '',
    artifact TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    target_value TEXT NOT NULL DEFAULT '',
    target_type TEXT NOT NULL DEFAULT '',
    workflow_id TEXT NOT NULL DEFAULT '',
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE artifact_stats (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL DEFAULT '',
    workflow_id TEXT NOT NULL,
    artifact TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    engine TEXT NOT NULL DEFAULT '',
    task TEXT NOT NULL DEFAULT '',
    targets INTEGER NOT NULL DEFAULT 0,
    tasks INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    results_count INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE action_records (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    artifact TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    input JSONB NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'candidate',
    workflow_id TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '',
    threads INTEGER NOT NULL DEFAULT 0,
    spray_dict TEXT NOT NULL DEFAULT '',
    nuclei_tags TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
