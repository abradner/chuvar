-- name: InsertAuditLog :exec
INSERT INTO audit_log (event_type, subject, fact_id, grant_id, staged_diff_id, scopes, grant_request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7);
