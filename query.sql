-- name: CreateUser :one
INSERT INTO auth (
  username, email, password_hash
) VALUES (
  $1, $2, $3
)
RETURNING id, username, email, created_at, last_updated;

-- name: GetUserByID :one
SELECT id, username, email, password_hash, created_at, last_updated FROM auth
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, username, email, password_hash, created_at, last_updated FROM auth
WHERE email = $1;

-- name: GetUserByUsername :one
SELECT id, username, email, password_hash, created_at, last_updated FROM auth
WHERE username = $1;

-- name: UpdateUserUsername :exec
UPDATE auth
  SET username = $2,
  last_updated = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: UpdateUserEmail :exec
UPDATE auth
  SET email = $2,
  last_updated = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE auth
  SET password_hash = $2,
  last_updated = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM auth
WHERE id = $1;

-- name: CreateOAuthIdentity :one
INSERT INTO oauth_identities (
  provider_user_id, provider, user_id
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: GetOAuthIdentity :one
SELECT * FROM oauth_identities
WHERE provider_user_id = $1 AND provider = $2;
