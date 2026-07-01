-- name: CreateWorkItem :exec
INSERT INTO work_items (id, campaign_id, batch_id, parent_id, type, target, artifact, queue, input, schedule, status, attempts, max_attempts, workflow_id, error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: GetWorkItem :one
SELECT id, campaign_id, batch_id, parent_id, type, target, artifact, queue, input, schedule, status, attempts, max_attempts, workflow_id, error, created_at, updated_at
FROM work_items WHERE id = $1;

-- name: ListWorkItems :many
SELECT id, campaign_id, batch_id, parent_id, type, target, artifact, queue, input, schedule, status, attempts, max_attempts, workflow_id, error, created_at, updated_at
FROM work_items
WHERE (campaign_id = $1 OR $1 = '')
  AND (batch_id = $2 OR $2 = '')
  AND (status = $3 OR $3 = '')
  AND (type = $4 OR $4 = '')
  AND (artifact = $5 OR $5 = '')
ORDER BY updated_at DESC
LIMIT $6 OFFSET $7;

-- name: CountWorkItemsByStatus :many
SELECT status, COUNT(*)::int as count FROM work_items WHERE campaign_id = $1 AND batch_id = $2 GROUP BY status;

-- name: CountRunningWorkItems :one
SELECT COUNT(*) FROM work_items WHERE status IN ('running','starting');

-- name: BulkUpdateWorkItemStatus :exec
UPDATE work_items SET status = $1, error = $2, updated_at = NOW()
WHERE batch_id = $3 AND status IN ('pending','starting','running','retry_waiting','paused');

-- name: DeleteWorkItemsByBatch :exec
DELETE FROM work_items WHERE batch_id = $1;
