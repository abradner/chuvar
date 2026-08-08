-- name: IncrementProposeWriteRateLimit :one
-- Atomically increments subject's counter for the given fixed window and
-- returns the post-increment count. ON CONFLICT DO UPDATE, not a separate
-- SELECT-then-INSERT/UPDATE: Postgres serializes concurrent upserts against
-- the same (subject, window_start) row via that row's own lock, which is what
-- closes the race between two concurrent proposals from the same subject —
-- see store.CheckProposeWriteRateLimit's doc comment.
INSERT INTO propose_write_rate_limits (subject, window_start, count)
VALUES ($1, $2, 1)
ON CONFLICT (subject, window_start)
DO UPDATE SET count = propose_write_rate_limits.count + 1
RETURNING count;
