-- name: CreatePolicy :exec
INSERT INTO policies (id, name, description, ports, threads, spray_dict, nuclei_tags)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListPolicies :many
SELECT id, name, description, ports, threads, spray_dict, nuclei_tags, created_at, updated_at
FROM policies
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: GetPolicy :one
SELECT id, name, description, ports, threads, spray_dict, nuclei_tags, created_at, updated_at
FROM policies
WHERE id = $1;

-- name: UpdatePolicy :exec
UPDATE policies
SET name = $1,
    description = $2,
    ports = $3,
    threads = $4,
    spray_dict = $5,
    nuclei_tags = $6,
    updated_at = NOW()
WHERE id = $7;

-- name: DeletePolicy :exec
DELETE FROM policies
WHERE id = $1;
