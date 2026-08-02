-- name: GetDataKey :one
SELECT purpose, wrapped_key, created_at, rotated_at FROM data_keys WHERE purpose = $1;

-- name: InsertDataKey :one
-- ON CONFLICT DO NOTHING rather than an upsert: two processes booting at once
-- must not each mint a DEK and have the second overwrite the first, because
-- anything the loser sealed in between would become unopenable. The conflicting
-- caller gets no row back and re-reads the winner's key instead — see
-- LoadOrCreateDataKey.
INSERT INTO data_keys (purpose, wrapped_key)
VALUES ($1, $2)
ON CONFLICT (purpose) DO NOTHING
RETURNING purpose, wrapped_key, created_at, rotated_at;

-- name: RewrapDataKey :execrows
-- Master-key rotation: replaces the wrapping without touching anything sealed
-- under the DEK itself. The DEK's plaintext bytes are unchanged by definition,
-- so no data is re-encrypted.
UPDATE data_keys SET wrapped_key = $2, rotated_at = now() WHERE purpose = $1;
