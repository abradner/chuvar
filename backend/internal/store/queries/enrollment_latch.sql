-- name: SetEnrollmentLatch :exec
-- Idempotent set-once: the first enrollment inserts the singleton row, every
-- later one conflicts on the pinned primary key and does nothing — latched_at
-- is never re-stamped, and no second row is ever created. Deliberately never
-- an UPDATE/DELETE path: the latch only ever goes from unset to set over the
-- lifetime of a deployment (principle 12), so clearing it is an out-of-band
-- operator action, not something any store method exposes.
INSERT INTO enrollment_latch (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- name: EnrollmentLatchSet :one
-- The durable half of createToken's enrollment gate. Unlike
-- CountEverEnrolledReviewerTokens/CountEverEnrolledWebAuthnCredentials, which
-- read mutable factor rows the break-glass recovery clears, this survives a
-- factor reset — so the gate stays closed against a factorless bootstrap or a
-- stolen bearer token racing the operator during re-enrollment.
SELECT EXISTS(SELECT 1 FROM enrollment_latch) AS latched;
