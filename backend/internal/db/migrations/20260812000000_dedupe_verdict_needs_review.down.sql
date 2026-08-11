-- Reverts the dedupe_verdict CHECK constraint to its original three-value
-- vocabulary. Data-losing if any row was written with 'needs_review' in the
-- meantime — same caveat as any down migration narrowing a CHECK constraint
-- after data existed; there is no lossless way to represent a needs_review
-- verdict in the narrower vocabulary.
ALTER TABLE staged_diffs DROP CONSTRAINT staged_diffs_dedupe_verdict_check;
ALTER TABLE staged_diffs ADD CONSTRAINT staged_diffs_dedupe_verdict_check
    CHECK (dedupe_verdict IN ('novel', 'duplicate', 'contradiction'));
