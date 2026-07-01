-- name: CreateBatchRun :exec
INSERT INTO batch_runs (id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetBatchRun :one
SELECT id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, created_at, updated_at
FROM batch_runs WHERE id = $1;

-- name: ListBatchRuns :many
SELECT id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, created_at, updated_at
FROM batch_runs ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: ListBatchRunsByCampaign :many
SELECT id, campaign_id, workflow_id, type, target, ports, status, total_chunks, completed, failed, created_at, updated_at
FROM batch_runs WHERE campaign_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: UpdateBatchRunStatus :exec
UPDATE batch_runs SET status = $1, updated_at = NOW() WHERE id = $2;

-- name: CountBatchRuns :one
SELECT COUNT(*) FROM batch_runs;

-- name: DeleteBatchRun :exec
DELETE FROM batch_runs WHERE id = $1;

-- name: CreateBatchChunk :exec
INSERT INTO batch_chunks (id, batch_id, target, chunk, workflow_id, status, error)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetBatchChunks :many
SELECT id, batch_id, target, chunk, workflow_id, status, error, created_at, updated_at
FROM batch_chunks WHERE batch_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3;

-- name: DeleteBatchChunks :exec
DELETE FROM batch_chunks WHERE batch_id = $1;
