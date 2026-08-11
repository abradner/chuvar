-- Best-effort revert: this migration only ever inserts the singleton latch
-- row, so undoing it means removing that row again. This is data-losing and
-- cannot distinguish "latched by this backfill" from "latched afterward by a
-- real enrollment" (store.CreateReviewerToken / store.CreateWebAuthnCredential
-- use the identical INSERT ... ON CONFLICT DO NOTHING against the same row) —
-- the same limitation the enrollment_latch migration's own down (DROP TABLE)
-- already has, unconditionally, for the same reason. Down migrations here are
-- a schema-development rollback tool, not a safe production action; see that
-- migration's down.sql.
DELETE FROM enrollment_latch;
