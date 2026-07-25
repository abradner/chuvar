-- name: InsertAuditLog :exec
INSERT INTO audit_log (event_type, subject, fact_id, grant_id, staged_diff_id, scopes)
VALUES ($1, $2, $3, $4, $5, $6);
