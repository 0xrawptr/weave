-- name: CreateAsset :exec
INSERT INTO assets (id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, status, lifecycle, raw_hash, source_run_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: GetAsset :one
SELECT id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, status, lifecycle, raw_hash, source_run_id, first_seen, last_seen, created_at
FROM assets WHERE id = $1;

-- name: ListAssets :many
SELECT id, campaign_id, type, value, source, target_id, raw_data, confidence, severity, status, lifecycle, raw_hash, source_run_id, first_seen, last_seen, created_at
FROM assets
WHERE (campaign_id = $1 OR $1 = '')
  AND (type = $2 OR $2 = '')
  AND (status = $3 OR $3 = '')
  AND (source = $4 OR $4 = '')
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: CountAssets :one
SELECT COUNT(*) FROM assets;

-- name: CountAssetsByType :many
SELECT type, COUNT(*)::int as count FROM assets GROUP BY type;

-- name: CountTodayAssets :one
SELECT COUNT(*) FROM assets WHERE created_at >= CURRENT_DATE;

-- name: CountAssetsByDate :one
SELECT COUNT(*) FROM assets WHERE created_at::date = $1;

-- name: CountVulnsByDate :one
SELECT COUNT(*) FROM assets WHERE type = 'vulnerability' AND created_at::date = $1;

-- name: UpdateAssetStatus :exec
UPDATE assets SET status = $1, last_seen = NOW() WHERE id = $2;

-- name: UpdateAssetRawData :exec
UPDATE assets SET raw_data = $1 WHERE type = 'ip' AND value = $2;

-- name: DeleteAssetsByCampaign :exec
DELETE FROM assets WHERE campaign_id = $1;

-- name: SaveRawEvent :exec
INSERT INTO raw_events (id, campaign_id, artifact, target_id, target_value, target_type, workflow_id, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
