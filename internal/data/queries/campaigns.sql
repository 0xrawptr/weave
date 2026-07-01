-- name: CreateCampaign :exec
INSERT INTO campaigns (id, name, description, status, phase, phase_reason)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListCampaigns :many
SELECT id, name, description, status, phase, phase_reason, created_at, updated_at
FROM campaigns
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: GetCampaign :one
SELECT id, name, description, status, phase, phase_reason, created_at, updated_at
FROM campaigns
WHERE id = $1;

-- name: UpdateCampaignStatus :exec
UPDATE campaigns SET status = $1, updated_at = NOW() WHERE id = $2;

-- name: CountActiveCampaigns :one
SELECT COUNT(*) FROM campaigns WHERE status = 'active';
