-- Fails fast with a clear message rather than letting the SET NOT NULL below
-- surface an opaque "column contains null values" error: a capability-kind row
-- has depth = NULL by design (the pairing constraint this migration added
-- requires it), so rolling back while any exist would otherwise fail
-- mid-migration with no indication of why. Found in review.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM grants WHERE kind != 'memory')
       OR EXISTS (SELECT 1 FROM grant_requests WHERE kind != 'memory') THEN
        RAISE EXCEPTION 'cannot roll back 20260730110000_grant_kind: capability-kind rows exist in grants/grant_requests (their depth is NULL by design, which restoring depth SET NOT NULL cannot satisfy) — delete or convert them to kind=memory first';
    END IF;
END $$;

ALTER TABLE grant_requests DROP CONSTRAINT grant_requests_kind_depth_pairing;
ALTER TABLE grant_requests ALTER COLUMN depth SET DEFAULT 'facts';
ALTER TABLE grant_requests ALTER COLUMN depth SET NOT NULL;
ALTER TABLE grant_requests DROP COLUMN kind;

ALTER TABLE grants DROP CONSTRAINT grants_kind_depth_pairing;
ALTER TABLE grants ALTER COLUMN depth SET DEFAULT 'facts';
ALTER TABLE grants ALTER COLUMN depth SET NOT NULL;
ALTER TABLE grants DROP COLUMN kind;
